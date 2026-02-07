Staging stack (Postgres + Redis) for AgriYogi

1) Copy `.env.example` to `.env` and set DATABASE_URL, e.g.: 

```powershell
copy .env.example .env
# Edit .env and set DATABASE_URL=postgresql://agriyogi:agriyogi_pass@localhost:5432/agriyogi
```

2) Start the staging stack:

```powershell
docker-compose -f docker-compose.staging.yml up --build -d
```

3) Initialize Postgres DB schema (if not using migration tool):

```powershell
# Optionally run the migration helper to copy data from local sqlite
# Ensure DATABASE_URL is set in environment or in .env
python migrate_to_postgres.py
```

4) Access app at http://127.0.0.1:5000

Notes:
- Postgres data is persisted in a Docker volume named `postgres_data`.
- Redis available at port 6379 for caching/session usage when configured.
- For production, follow `PRODUCTION_DEPLOYMENT.md` to run behind Nginx and use systemd.
