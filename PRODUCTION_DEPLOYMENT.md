# AgriYogi - Production Deployment Guide

## System Requirements

```
OS: Ubuntu 22.04 LTS or CentOS 8+
Python: 3.11+
Memory: 2GB minimum (4GB recommended)
Storage: 10GB for database + backups
CPU: 2 cores minimum
```

## Pre-Deployment Checklist

### 1. Environment Configuration
```bash
cd /opt/agriyogi
cp .env.example .env
# Edit .env with production values
```

### 2. Critical Environment Variables
```bash
FLASK_ENV=production
FLASK_SECRET=<generate-32-char-random-string>
SECURE_COOKIES=True
DATABASE_URL=postgresql://user:password@localhost/agriyogi
```

### 3. Generate Secure Secret Key
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Installation Steps

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/agriyogi.git /opt/agriyogi
cd /opt/agriyogi
```

### 2. Create Python Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### 4. Initialize Database
```bash
python3 -c "from blockchain import init_db; init_db(); print('Database initialized')"
```

### 5. Create Required Directories
```bash
mkdir -p logs backups
chmod 755 logs backups
```

## Running with Gunicorn

### Configuration File: gunicorn_config.py
```python
import multiprocessing

bind = "127.0.0.1:8000"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 4
worker_class = "gthread"
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
preload_app = True

errorlog = "logs/gunicorn_error.log"
accesslog = "logs/gunicorn_access.log"
loglevel = "info"
```

### Start Server
```bash
gunicorn --config gunicorn_config.py web_app:app
```

## Nginx Configuration

### /etc/nginx/sites-available/agriyogi
```nginx
upstream agriyogi {
    server 127.0.0.1:8000;
    server 127.0.0.1:8001;
    server 127.0.0.1:8002;
}

server {
    listen 80;
    server_name agriyogi.example.com www.agriyogi.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name agriyogi.example.com www.agriyogi.example.com;

    # SSL Certificates (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/agriyogi.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/agriyogi.example.com/privkey.pem;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Gzip Compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
    gzip_min_length 1024;

    # Proxy Settings
    proxy_cache_path /var/cache/nginx/agriyogi levels=1:2 keys_zone=agriyogi_cache:10m;
    proxy_cache agriyogi_cache;
    proxy_cache_valid 200 10m;

    location / {
        proxy_pass http://agriyogi;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    location /static/ {
        alias /opt/agriyogi/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location /health {
        proxy_pass http://agriyogi;
        access_log off;
    }
}
```

### Enable Site
```bash
sudo ln -s /etc/nginx/sites-available/agriyogi /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## SSL/TLS Setup (Let's Encrypt)

```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot certonly --nginx -d agriyogi.example.com -d www.agriyogi.example.com
```

## Systemd Service File

### /etc/systemd/system/agriyogi.service
```ini
[Unit]
Description=AgriYogi Farm Blockchain Platform
After=network.target

[Service]
Type=notify
User=agriyogi
WorkingDirectory=/opt/agriyogi
Environment="PATH=/opt/agriyogi/venv/bin"
EnvironmentFile=/opt/agriyogi/.env
ExecStart=/opt/agriyogi/venv/bin/gunicorn \
    --config gunicorn_config.py \
    --bind 127.0.0.1:8000 \
    web_app:app
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
KillSignal=SIGTERM
Restart=on-failure
RestartSec=10
StandardOutput=append:/opt/agriyogi/logs/service.log
StandardError=append:/opt/agriyogi/logs/service.log

[Install]
WantedBy=multi-user.target
```

### Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable agriyogi
sudo systemctl start agriyogi
sudo systemctl status agriyogi
```

## Database Setup (PostgreSQL)

### Install PostgreSQL
```bash
sudo apt-get install postgresql postgresql-contrib
```

### Create Database
```bash
sudo -u postgres psql
CREATE USER agriyogi WITH PASSWORD 'strong-password';
CREATE DATABASE agriyogi OWNER agriyogi;
GRANT ALL PRIVILEGES ON DATABASE agriyogi TO agriyogi;
\q
```

### Migration from SQLite
```bash
# Backup SQLite database
cp ledger.db ledger.db.backup

# Update DATABASE_URL in .env
DATABASE_URL=postgresql://agriyogi:password@localhost/agriyogi

# Run migration script
python3 migrate_to_postgres.py
```

## Monitoring & Health Checks

### Health Check Endpoint
```bash
curl https://agriyogi.example.com/health
```

### Prometheus Metrics (optional)
```bash
# Install prometheus_client
pip install prometheus-client

# Scrape endpoint: /metrics
```

### Log Monitoring
```bash
# Watch logs in real-time
tail -f logs/agriyogi.log

# Check for errors
grep ERROR logs/agriyogi.log
```

## Backup Strategy

### Automated Daily Backup
```bash
#!/bin/bash
# /opt/agriyogi/backup.sh

BACKUP_DIR="/opt/agriyogi/backups"
DB_NAME="agriyogi"
DATE=$(date +%Y%m%d_%H%M%S)

# PostgreSQL dump
pg_dump -U agriyogi $DB_NAME | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# Keep only last 30 days
find $BACKUP_DIR -name "db_*.sql.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

### Cron Job
```bash
# Add to crontab
0 2 * * * /opt/agriyogi/backup.sh >> /opt/agriyogi/logs/backup.log 2>&1
```

## Security Hardening

### Firewall Configuration
```bash
sudo ufw enable
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw deny 5000/tcp   # Flask dev server
```

### File Permissions
```bash
sudo chown -R agriyogi:agriyogi /opt/agriyogi
chmod 750 /opt/agriyogi
chmod 600 /opt/agriyogi/.env
chmod 755 /opt/agriyogi/logs
```

### SSH Key Authentication
```bash
# Disable password authentication in /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
```

### Fail2Ban Setup
```bash
sudo apt-get install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

## Performance Tuning

### PostgreSQL Connection Pool
```python
# In blockchain.py
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_recycle=3600
)
```

### Database Indexes
```sql
CREATE INDEX idx_blocks_author ON blocks(author);
CREATE INDEX idx_blocks_timestamp ON blocks(timestamp DESC);
CREATE INDEX idx_users_username ON users(username UNIQUE);
```

### Cache Configuration
```python
# Add Redis caching
from flask_caching import Cache

cache = Cache(app, config={'CACHE_TYPE': 'redis'})
```

## Monitoring & Alerting

### Datadog Integration (Optional)
```bash
DD_API_KEY=your-key DD_SITE=datadoghq.com bash -c \
  "$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_agent.sh)"
```

### CloudWatch Metrics (AWS)
```python
import boto3

cloudwatch = boto3.client('cloudwatch')
cloudwatch.put_metric_data(
    Namespace='AgriYogi',
    MetricData=[
        {
            'MetricName': 'BlockchainLength',
            'Value': len(blockchain.get_chain())
        }
    ]
)
```

## Troubleshooting

### Service Won't Start
```bash
sudo systemctl status agriyogi -l
tail -f /opt/agriyogi/logs/service.log
```

### High CPU Usage
```bash
# Check Gunicorn workers
ps aux | grep gunicorn

# Reduce workers in gunicorn_config.py if needed
```

### Database Connection Issues
```bash
# Test PostgreSQL connection
psql -U agriyogi -d agriyogi -h localhost
```

### SSL Certificate Renewal
```bash
sudo certbot renew --nginx
# Auto-renewal runs daily via cron
```

## Rollback Procedure

```bash
# If new deployment has issues:
1. Stop current version
   sudo systemctl stop agriyogi

2. Restore previous code
   git revert HEAD
   git pull

3. Restore database backup
   pg_restore -U agriyogi -d agriyogi backups/db_*.sql.gz

4. Restart service
   sudo systemctl start agriyogi
```

## Performance Baselines

| Metric | Target | Monitoring |
|--------|--------|-----------|
| Response Time (p95) | < 150ms | Prometheus |
| Error Rate | < 0.1% | CloudWatch |
| CPU Usage | < 70% | Top/Datadog |
| Memory Usage | < 80% | Free/Datadog |
| Database Connections | < 20 | pg_stat_activity |
| Disk Usage | < 85% | df -h |

## Support & Escalation

**Issues:** Create GitHub issue with logs
**Security:** security@agriyogi.example.com
**On-Call:** PagerDuty (if applicable)

---

*Last Updated: February 2, 2026*
