# Shared image for both the Flask API and the Celery worker — they need
# the exact same code and dependencies, just a different CMD (set in
# docker-compose.yml). Building one image instead of two keeps them from
# ever drifting out of sync with each other.

FROM python:3.12-slim

WORKDIR /app

# System deps: none needed beyond what python:slim ships with — the
# scanner modules use stdlib ssl/socket, and lxml's wheel is manylinux
# so it doesn't need a C toolchain at install time.

COPY api/requirements.txt ./api/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt

# scanner/ is imported by celery_worker.py via a relative sys.path
# insert, so it needs to sit alongside api/ inside the image the same
# way it does in the repo.
COPY scanner/ ./scanner/
COPY api/ ./api/

WORKDIR /app/api

# Default command runs the API via gunicorn (production WSGI server —
# NOT `python app.py`, which uses Flask's dev server and is unsafe to
# expose). docker-compose overrides this command for the worker service.
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "60", "app:app"]
