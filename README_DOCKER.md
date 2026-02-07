Quick Docker instructions for AgriYogi

1) Copy the example environment file and set a secure secret:

```bash
cd "C:\Users\smand\Desktop\blockchain_site"
copy .env.example .env
# Edit .env and set FLASK_SECRET to a 32+ char random string
```

2) Build and run with docker-compose (Linux/macOS/Windows with Docker Desktop):

```bash
docker-compose up --build -d
# View logs
docker-compose logs -f
# Stop
docker-compose down
```

3) If you prefer Docker CLI directly:

```bash
docker build -t agriyogi .
docker run -p 5000:5000 --env-file .env -v %cd%:/app agriyogi
```

Notes:
- The service exposes the app on port 5000. Open http://127.0.0.1:5000
- Ensure `.env` contains production values (set `FLASK_SECRET`, `SECURE_COOKIES=True` when using HTTPS)
- For production, run behind Nginx as described in `PRODUCTION_DEPLOYMENT.md`
