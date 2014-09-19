#!/usr/bin/env python
# encoding: utf-8

import os
import time
import logging

from fabric.context_managers import settings
from fabric.api import env, sudo, put
from rq import get_current_job

from providers import registry

from utils import decrypt_key, get_user_directory, get_user_log_directory
from worker.exceptions import NoSuchProvider



def get_logger(username=None):
    if username is None:
        job = get_current_job()
        username = job.args[0]['username']
    user_directory = get_user_directory(username)
    logger = logging.getLogger(username)
    logger.setLevel(logging.DEBUG)
    log_directory = get_user_log_directory(username)
    handler = logging.FileHandler(os.path.join(log_directory, job.id))
    logger.addHandler(handler)
    return logger


def instance_action(data):
    action = data['instanceAction']
    provider = init_provider(data)
    instance = provider.get_instance(data['instanceId'])
    method_action = getattr(instance, action)
    method_action()
    return {"instance_id": instance.instance_id, "state":
            instance.instance.state}


def install_docker(package_name, params):
    with settings(warn_only=True):
        sudo('apt-get update')
    sudo('apt-get install -y docker.io')
    sudo('sudo ln -sf /usr/bin/docker.io /usr/local/bin/docker')
    # sudo('service docker start')
    port_part = " ".join(["-p {port}:{port}".format(port=port)
        for port in params.get("ports", [])])
    env_part = " ".join(["-e {key}={value}".format(key=key, value=value)
        for key, value in params.get("env", {}).items()])
    env_part = env_part.format(host=env.host_string)
    run_cmd = "docker run {envs} -d -i -t {ports} {name}:{tag} {cmd}".format(
        envs=env_part, ports=port_part, name=package_name,
        tag=params.get("tag", ""), cmd=params.get('cmd', ''))
    with settings(warn_only=True):
        sudo('docker pull {package_name}'.format(package_name=package_name))
        sudo(run_cmd)


def get_provider_class(provider):
    try:
        return registry[provider]
    except KeyError:
        raise NoSuchProvider()


def init_provider(data, not_job=False):
    if not_job:
        logger = None
    else:
        logger = get_logger()
    provider_name = data['cloudProvider']
    Provider = get_provider_class(provider_name)
    provider = Provider(data, logger=logger)
    return provider



def deploy(data):
    logger = get_logger()
    provider = init_provider(data)
    if 'instanceId' in data:
        instance = provider.get_instance(data['instanceId'])
    else:
        instance = provider.create_instance()
    with instance.ssh():
        logger.info("Installing package to {}".format(instance))
        install_docker(data['packageName'], data['dockerParams'])

    return {"instance_id": instance.instance_id, "public_dns":
            instance.host}
