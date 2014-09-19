import os.path
import time
import zope.interface

import boto.ec2

from base import IProvider, MixinProvider, IInstance, MixinInstance

import logging
import logging.handlers

from utils import decrypt_key, get_user_directory

from worker.exceptions import InstanceDoesNotExist, InstanceException
from config import USER_DIRECTORY, SSH_PORT, HTTPS_PORT, HTTP_PORT, \
        SECURITY_GROUP_NAME


class AmazonProvider(MixinProvider):
    zope.interface.implements(IProvider)

    provider_name = "amazon"

    cidr = '0.0.0.0/0'
    default_region = 'us-west-2'
    default_ami = 'ami-2d9add1d'
    default_instance_type = 't1.micro'

    def __init__(self, params, **kwargs):
        super(AmazonProvider, self).__init__(params, **kwargs)
        self._connection = None

    @property
    def connection(self):
        return self._connection or self._connect()

    def _connect(self):
        params = self.init_data
        access_key = decrypt_key(params['apiKey'])
        secret_key = decrypt_key(params['secretKey'])
        region = params.get('region', self.default_region)
        self._connection = boto.ec2.connect_to_region(
            region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
            )
        return self._connection

    def create_instance(self):
        self.logger.debug("Spinning up new instance")
        self._create_key()
        self._create_security_group()

        ami = self.init_data.get("instanceAmi", self.default_ami)
        instance_type = self.init_data.get("instanceType",
                self.default_instance_type)
        reservation = self.connection.run_instances(
                ami,
                key_name=self.keyname,
                security_groups=[SECURITY_GROUP_NAME],
                instance_type=instance_type
                )
        instance = reservation.instances[0]
        status = instance.update()
        self.logger.debug("Waiting for instance to start")
        while status == 'pending':
            time.sleep(3)
            status = instance.update()

        instance = self.get_instance(instance.id)
        self.logger.info("New aws instance created: {}".format(instance))
        return instance

    def get_instance(self, instance_id):
        return AmazonInstance(self, instance_id)

    def _create_security_group(self):
        try:
            group = self.connection.get_all_security_groups(groupnames=[SECURITY_GROUP_NAME])[0]
        except self.connection.ResponseError, e:
            if e.code == 'InvalidGroup.NotFound':
                # create new group
                self.logger.info("Create new amazon security group {}".format(
                    SECURITY_GROUP_NAME))
                group = self.connection.create_security_group(SECURITY_GROUP_NAME,
                        "Xervmon security group")
            else:
                self.logger.error(
                    "Could not create the security group {}".format(e.code)
                    )
                raise

        for port in (SSH_PORT, HTTP_PORT, HTTPS_PORT):
            try:
                group.authorize('tcp', port, port, self.cidr)
                self.logger.debug("Authorize port {} inside group".format(
                    port))
            except self.connection.ResponseError, e:
                if e.code == 'InvalidPermission.Duplicate':
                    # Already exists
                    pass
                else:
                    self.logger.error(
                        "Could not authorize the port for security group {}".format(e.code)
                        )
                    raise

    def _create_key(self):
        try:
            key = self.connection.get_all_key_pairs(keynames=[self.keyname])[0]
        except self.connection.ResponseError, e:
            if e.code == 'InvalidKeyPair.NotFound':
                self.logger.info("Creating new security key")
                key = self.connection.create_key_pair(self.keyname)
                key.save(self.user_directory)
                self.logger.info(
                    "Saving security key to {}".format(self.user_directory)
                    )
            else:
                self.logger.error(
                    "Could not create security key {}".format(e.code)
                    )
                raise



class AmazonInstance(MixinInstance):
    zope.interface.implements(IInstance)

    default_user = 'ubuntu'

    def __init__(self, provider, instance_id):
        super(AmazonInstance, self).__init__(provider, instance_id)
        self._get_instance()

    def _get_instance(self):
        try:
            self.instance = self.provider.connection.get_only_instances(
                instance_ids=(self.instance_id, ))[0]
        except IndexError:
            raise InstanceDoesNotExist(self)

    @property
    def host(self):
        return self.instance.public_dns_name

    @property
    def user(self):
        return self.default_user

    def start(self):
        self.logger.info("Starting the instance {}".format(self))
        self.instance.start()

    def stop(self):
        self.logger.info("Stopping the instance {}".format(self))
        self.instance.stop()

    def terminate(self):
        self.logger.info("Terminating the instance {}".format(self))
        self.instance.terminate()
