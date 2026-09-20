#!/bin/bash
celery -A celery_worker worker --loglevel=info --concurrency=2 &
exec gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --threads 4 --timeout 60 app:app
