"""
🔄 Celery Application - Background task processing for SecureScan Framework
"""

from celery import Celery
from celery.signals import setup_logging as celery_setup_logging
from app.core.config import get_settings

# =============================================================================
# 📋 CELERY CONFIGURATION
# =============================================================================

settings = get_settings()

# Create Celery instance
celery_app = Celery(
    "securescan",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.scan_tasks",
        "app.workers.notification_tasks",
        "app.workers.cleanup_tasks"
    ]
)

# Celery configuration
celery_app.conf.update(
    # Task routing
    task_routes={
        "app.workers.scan_tasks.*": {"queue": "scans"},
        "app.workers.notification_tasks.*": {"queue": "notifications"},
        "app.workers.cleanup_tasks.*": {"queue": "cleanup"}
    },
    
    # Task settings
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=3600,  # 1 hour
    timezone="UTC",
    enable_utc=True,
    
    # Worker settings
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    worker_disable_rate_limits=False,
    
    # Result backend settings
    result_backend_transport_options={
        "master_name": "mymaster"
    },
    
    # Security
    worker_hijack_root_logger=False,
    worker_log_color=False
)

# Override Celery's logging setup
@celery_setup_logging.connect
def setup_celery_logging(loglevel=None, logfile=None, format=None, colorize=None, **kwargs):
    """Configure Celery logging to use our logger"""
    pass  # Use our existing logging configuration


# Task discovery
celery_app.autodiscover_tasks([
    "app.workers.scan_tasks",
    "app.workers.notification_tasks", 
    "app.workers.cleanup_tasks"
])

# Export for imports
__all__ = ["celery_app"]