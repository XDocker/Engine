from __future__ import absolute_import

from celery import Celery

from . import config

celery = Celery(config.CELERY_PREFIX, broker=config.CELERY_BROKER_URL)
celery.config_from_object(config)
