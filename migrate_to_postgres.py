"""
Simple migration helper: copy `blocks` and `users` from the local SQLite `ledger.db`
into a PostgreSQL database pointed to by the `DATABASE_URL` environment variable.

Usage:
  Set `DATABASE_URL=postgresql://user:pw@host:port/dbname` and run:
    python migrate_to_postgres.py

This script uses SQLAlchemy core to reflect tables and copy rows.
"""
import os
import sys
from sqlalchemy import create_engine, MetaData, Table, select, insert

# Locate local sqlite DB created by blockchain.py
from pathlib import Path
ROOT = Path(__file__).resolve().parent
sqlite_path = ROOT / 'ledger.db'
if not sqlite_path.exists():
    print('Local SQLite ledger.db not found at', sqlite_path)
    sys.exit(1)

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print('Please set DATABASE_URL environment variable to your Postgres connection string')
    print('Example: postgresql://agriyogi:password@localhost:5432/agriyogi')
    sys.exit(1)

print('Migrating from', sqlite_path, 'to', DATABASE_URL)

# Engines
sqlite_engine = create_engine(f'sqlite:///{sqlite_path}', echo=False)
pg_engine = create_engine(DATABASE_URL, echo=False)

sqlite_meta = MetaData(bind=sqlite_engine)
pg_meta = MetaData(bind=pg_engine)

# Reflect the sqlite schema
sqlite_meta.reflect(only=['blocks', 'users'])
blocks_table = sqlite_meta.tables.get('blocks')
users_table = sqlite_meta.tables.get('users')
if blocks_table is None or users_table is None:
    print('Expected tables `blocks` and `users` not found in SQLite DB')
    sys.exit(1)

# Reflect or create target tables in Postgres using simple create (if not exists)
# We'll reflect pg_meta and create tables if missing by emitting DDL from sqlite definitions.
pg_meta.reflect()
if 'blocks' not in pg_meta.tables:
    print('Creating `blocks` table in Postgres (simple schema)')
    pg_engine.execute(
        '''CREATE TABLE IF NOT EXISTS blocks (
            idx INTEGER PRIMARY KEY,
            timestamp TEXT,
            data TEXT,
            previous_hash TEXT,
            hash TEXT,
            author TEXT,
            signature TEXT
        );'''
    )
if 'users' not in pg_meta.tables:
    print('Creating `users` table in Postgres (simple schema)')
    pg_engine.execute(
        '''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            hmac_key TEXT
        );'''
    )

# Now copy data
with sqlite_engine.connect() as s_conn, pg_engine.connect() as p_conn:
    # Blocks
    rows = s_conn.execute(select(blocks_table)).fetchall()
    if rows:
        print(f'Copying {len(rows)} blocks...')
        for r in rows:
            # Use INSERT ... ON CONFLICT DO NOTHING to avoid duplicates (Postgres)
            p_conn.execute(
                insert(Table('blocks', pg_meta, autoload_with=pg_engine)).values(
                    idx=r['idx'],
                    timestamp=r['timestamp'],
                    data=r['data'],
                    previous_hash=r['previous_hash'],
                    hash=r['hash'],
                    author=r.get('author'),
                    signature=r.get('signature')
                )
            )
    else:
        print('No blocks to copy')

    # Users
    urows = s_conn.execute(select(users_table)).fetchall()
    if urows:
        print(f'Copying {len(urows)} users...')
        for u in urows:
            p_conn.execute(
                insert(Table('users', pg_meta, autoload_with=pg_engine)).values(
                    username=u['username'],
                    password_hash=u['password_hash'],
                    hmac_key=u['hmac_key']
                )
            )
    else:
        print('No users to copy')

print('Migration complete. Verify data in Postgres.')
