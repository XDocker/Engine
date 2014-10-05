#!/usr/bin/env python
# encoding: utf-8

import os
import time

from fabric.context_managers import settings
from fabric.api import env, sudo, put
from rq import get_current_job

from providers import registry

from config import MAX_INSTALL_RETRY
from utils import decrypt_key, get_user_directory, get_user_log_directory, \
        get_logger, install_remote_logger
from worker.exceptions import NoSuchProvider, InstanceDoesNotExist, \
        DeployException



def instance_action(data):
    action = data['instanceAction']
    instance_id = data['instanceId']
    provider = init_provider(data)
    try:
        instance = provider.get_instance(instance_id)
    except InstanceDoesNotExist:
        provider.logger.warning(
                "Instance {} does not exist".format(instance_id))
        raise
    method_action = getattr(instance, action)
    method_action()
    return {"instance_id": instance_id, "state":
            instance.instance.state}


def install_docker(package_name, params):
    install_remote_logger('paramiko')
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
    provider_name = provider.lower()
    try:
        return registry[provider_name]
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
        # install_docker(data['packageName'], data['dockerParams'])
        i = 0
        failed = True
        while i < MAX_INSTALL_RETRY:
            if i > 0:
                logger.info("Trying install package one more time")
            try:
                install_docker(data['packageName'], data['dockerParams'])
                failed = False
                break
            except Exception, e:
                logger.error("Error installing {}".format(str(e)))
                time.sleep(5)
                i += 1
    if failed:
        logger.error("Could not deploy docker package")
        raise DeployException()

    return {"instance_id": instance.instance_id, "public_dns":
            instance.host}
