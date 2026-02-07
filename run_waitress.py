"""Run AgriYogi with Waitress (Windows-friendly production runner)
Usage: python run_waitress.py
"""
from waitress import serve
import os

# Ensure correct app import path
from web_app import app

if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting AgriYogi via Waitress on {host}:{port}")
    serve(app, host=host, port=port, threads=8)
