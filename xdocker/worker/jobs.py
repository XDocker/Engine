#!/usr/bin/env python
# encoding: utf-8

import os
import re
import time
import json
from fabric.context_managers import settings
from fabric.api import env, sudo, put
from rq import get_current_job

from providers import registry

from config import DEPS_FILE
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


braced_param = re.compile("{(\w+)}")

def install_docker(package_name, params, instance, deps):
    install_remote_logger('paramiko')
    logger = get_logger()
    try:
        for cmd in deps['dependencies']:
            sudo(cmd)
    except Exception as e:
        logger.error("Error processing dependencies commands")
    # sudo('service docker start')
    port_part = " ".join(["-p {port}:{port}".format(port=port)
        for port in params.get("ports", [])])

    env_part = ""
    instance_envs = instance.get_envs()
    for key, value in params.get("env", {}).items():
        param_var = braced_param.search(value)
        if param_var:
            var_name = param_var.group(1)
            if not var_name in instance_envs:
                logger.warning("{} has no {} env param".format(instance,
                    var_name))
                continue
            else:
                value = instance_envs[var_name]
        env_part += "-e {key}={value} ".format(key=key, value=value)
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


def init_dependenices(os):
    deps = {}
    logger = get_logger()
    try:
        with open(DEPS_FILE) as data_file:
            data = json.load(data_file)
    except StandardError:
        logger.error("Error reading dependecies file {}".format(DEPS_FILE))
        return
    try:
        deps = data['OS'][os]
    except KeyError:
        logger.error("Error: can't find dependencies for OS: {}".format(os))
        return
    return deps


def deploy(data):
    deps = init_dependenices(data['OS'])
    logger = get_logger()
    provider = init_provider(data)
    if 'instanceId' in data:
        instance = provider.get_instance(data['instanceId'])
    else:
        instance = provider.create_instance()
    with instance.ssh():
        logger.info("Installing package to {}".format(instance))
        i = 0
        failed = True
        time.sleep(20)
        while i < MAX_INSTALL_RETRY:
            if i > 0:
                logger.info("Trying install package one more time")
            try:
                install_docker(data['packageName'], data['dockerParams'],
                        instance, deps)
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
            instance.host, "state": instance.state}


def sourceBillingData(data):
    logger = get_logger()
    provider = init_provider(data)
    # Here if billing bucket is provided - then get the contents csv files
    # Suggestion : we load the files located based on the date stamp.
    # This can be loaded to mongo for each user.
    # Then we summarize this data - monthly, quarterly, half yearly, yearly, group by AWS assets per month, per quarter
    # - Resource or tag wise and so on.
    # Note : Then we use https://pypi.python.org/pypi/django-aws-billing/0.2.6 and implement the methods
    return ''
