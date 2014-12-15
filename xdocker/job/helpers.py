import os
import re
import logging
import logging.handlers

from flask.ext.login import current_user

from ..config import USER_DIRECTORY, LOG_DIRECTORY_NAME
from ..celery import celery
from ..app_exceptions import PermissionDenied
from ..tasks.worker_exceptions import WorkerException
from .utils import tail


LOGGER_HANDLER_NAME = "xdocker"

def get_job_status(job_id):
    res_dict = {}

    if not job_id in current_user.jobs:
        raise PermissionDenied(current_user)
    job = celery.AsyncResult(job_id)
    if job:
        status = job.status
        result = job.result
        if result:
            result_type = type(result)
            if issubclass(result_type, Exception):
                res_dict['fail'] = True
                if issubclass(result_type, WorkerException):
                    res_dict['fail_code'] = result.code
                    res_dict['fail_message'] = result.message
                result = None
        res_dict['result'] = result
    else:
        status = None

    if status == 'FAILURE':
        status = 'failed'
    elif status == 'SUCCESS':
        status = 'Completed'
    elif status == 'STARTED':
        status = 'started'

    res_dict['job_status'] = status
    return res_dict


def get_job_log(username, job_id, line_num=10):
    log_dir = get_user_log_directory(username)
    job_fp = os.path.join(log_dir, '{}'.format(job_id))
    if not os.path.exists(job_fp):
        return []

    if line_num > 100:
        line_num = 100
    with open(job_fp) as fp:
        return tail(fp, line_num)


def get_logger(username=None):
    if not username:
        return
    user_directory = get_user_directory(username)
    logger = logging.getLogger(username)
    if not logger.handlers or not LOGGER_HANDLER_NAME in map(lambda l:l.name,
            logger.handlers):
        log_directory = get_user_log_directory(username)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler = logging.FileHandler(os.path.join(log_directory,
            celery.current_task.request.id))
        handler.setFormatter(formatter)
        handler.setLevel(logging.INFO)
        handler.name = LOGGER_HANDLER_NAME
        logger.addHandler(handler)
    return logger


def get_user_directory(username):
    directory = os.path.join(USER_DIRECTORY, username)
    if not os.path.exists(directory):
        os.mkdir(directory)
    return directory


def get_user_log_directory(username):
    user_dir = get_user_directory(username)
    log_dir = os.path.join(user_dir, LOG_DIRECTORY_NAME)
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)
    return log_dir
