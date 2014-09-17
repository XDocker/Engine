#!/usr/bin/env python
# encoding: utf-8

import sys
import time
import os
import json
import logging
import logging.handlers

import boto.ec2

from fabric.context_managers import settings
from fabric.api import env, sudo, put


ROOT_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), os.pardir)

SSH_PORT = 22
HTTP_PORT = 80
HTTPS_PORT = 443

SECURITY_GROUP_NAME = 'xervmon'
KEY_NAME = 'xervmon'
KEY_EXTENSION = '.pem'
KEY_DIRECTORY = os.path.join(ROOT_PATH, 'keys')


logger = None


def get_logger():
    pass



def main(settings_file):
    with open(settings_file) as fp:
        data = json.load(fp)
    username = data['username']
    password = decrypt_key(data['password'])
    region = data.get('region', DEFAULT_REGION)
    access_key = decrypt_key(data['AWS_ACCESS'])
    secret_key = decrypt_key(data['AWS_SECRET'])

    user_directory = os.path.join(KEY_DIRECTORY, username)
    if not os.path.exists(user_directory):
        os.makedirs(user_directory)
    key_path = os.path.join(user_directory, "{}{}".format(KEY_NAME,
        KEY_EXTENSION))

    conn = boto.ec2.connect_to_region(
            region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
            )

    try:
        key = conn.get_all_key_pairs(keynames=[KEY_NAME])[0]
    except conn.ResponseError, e:
        if e.status == 403:
            print "Wrong keys"
            sys.exit(1)
        if e.code == 'InvalidKeyPair.NotFound':
            # create new key pair
            key = conn.create_key_pair(KEY_NAME)
        else:
            raise
        key.save(user_directory)

    try:
        group = conn.get_all_security_groups(groupnames=[SECURITY_GROUP_NAME])[0]
    except conn.ResponseError, e:
        if e.code == 'InvalidGroup.NotFound':
            # create new group
            group = conn.create_security_group(SECURITY_GROUP_NAME,
                    "Xervmon security group")
        else:
            raise
    for port in (SSH_PORT, HTTP_PORT, HTTPS_PORT):
        try:
            group.authorize('tcp', port, port, CIDR)
        except conn.ResponseError, e:
            if e.code == 'InvalidPermission.Duplicate':
                # Already exists
                pass
            else:
                raise

    # reservation = conn.run_instances(
    #         DEFAULT_AMI,
    #         key_name=KEY_NAME,
    #         security_groups=[SECURITY_GROUP_NAME],
    #         instance_type=DEFAULT_INSTANCE_TYPE
    #         )
    reservation = conn.get_all_instances()[0]
    instance = reservation.instances[0]
    while instance.state != 'running':
        time.sleep(5)
        instance.update()

    host = instance.public_dns_name
    import ipdb;ipdb.set_trace()

    with settings(key_filename=key_path, host_string=host,
            user=DEFAULT_USER):
        configure_instance()


def configure_instance():
    install_docker()
    with settings(warn_only=True):
        result = sudo('''docker run -e "mail=info@xervmon.com" -e "host={}" \
                -i -t -p 443:443 -p 5000:5000 xervmon/securitymonkey:v1 \
                /home/ubuntu/securitymonkey.sh'''.format(env.host_string))
        if result.failed:
            print result.stdout



if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "No data file"
        sys.exit(1)
    settings_file = sys.argv[1]
    main(settings_file)

