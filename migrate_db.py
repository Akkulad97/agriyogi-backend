import sqlite3
import os

db_file = os.path.join(os.path.dirname(__file__), 'ledger.db')

# Backup
import shutil
shutil.copy(db_file, db_file + '.backup')
print(f'Backed up to {db_file}.backup')

conn = sqlite3.connect(db_file)
c = conn.cursor()

# Add missing columns if they don't exist
try:
    c.execute("ALTER TABLE blocks ADD COLUMN photo_base64 TEXT")
    print('Added photo_base64 column')
except sqlite3.OperationalError as e:
    print(f'photo_base64 column: {e}')

try:
    c.execute("ALTER TABLE blocks ADD COLUMN verified_by TEXT")
    print('Added verified_by column')
except sqlite3.OperationalError as e:
    print(f'verified_by column: {e}')

conn.commit()
conn.close()
print('Migration complete!')
