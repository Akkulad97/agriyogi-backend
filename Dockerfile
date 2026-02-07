FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . /app

# Ensure logs directory exists
RUN mkdir -p /app/logs

ENV FLASK_ENV=production
ENV FLASK_APP=web_app:app
ENV PORT=5000

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "web_app:app", "--workers=3", "--threads=4", "--timeout=120"]
