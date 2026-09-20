"""
api/celery_app.py — Celery application instance.

Kept separate from celery_worker.py (the task definitions) and app.py
(the Flask server) so each piece can be imported independently:
  - Flask imports celery_app to queue tasks
  - The worker process imports celery_worker (which imports celery_app)
  - Tests can import celery_app without pulling in Flask
"""

import os

from celery import Celery

# Both broker and result backend point at the same local Redis instance.
# In production these would come from environment variables, not be
# hardcoded — REDIS_URL below already respects an env override.
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "vulnscan_lite",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=3600,  # scan results auto-expire from Redis after 1 hour
    task_track_started=True,
)
