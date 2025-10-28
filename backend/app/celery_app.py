from celery import Celery

from .config import settings

celery_app = Celery(
    "buh",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.autodiscover_tasks(["app.tasks"])
