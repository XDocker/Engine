import os.path
import time
import zope.interface
import json

import boto
import boto.ec2

from base import IProvider, MixinProvider, IInstance, MixinInstance

import logging

from utils import decrypt_key, get_user_directory, install_remote_logger

from worker.exceptions import InstanceDoesNotExist, InstanceException
from config import USER_DIRECTORY, SSH_PORT, HTTPS_PORT, HTTP_PORT, \
        SECURITY_GROUP_NAME


class AmazonProvider(MixinProvider):
    zope.interface.implements(IProvider)

    provider_name = "amazon aws"

    cidr = '0.0.0.0/0'
    default_region = 'us-west-2'
    default_ami = 'ami-2d9add1d'
    default_instance_type = 't1.micro'

    instance_name_tag = 'Name'

    def __init__(self, params, **kwargs):
        self.region = params.get('instanceRegion', self.default_region)

        super(AmazonProvider, self).__init__(params, **kwargs)

        self._connection = None
        self.access_key = decrypt_key(params['apiKey'])
        self.secret_key = decrypt_key(params['secretKey'])
        self.iam = None

        install_remote_logger('boto')

    def _make_keyname(self):
        default_keyname = super(AmazonProvider, self)._make_keyname()
        if 'keyname' in self.init_data:
            return default_keyname
        else:
            return '{}_{}'.format(default_keyname, self.region)

    @property
    def connection(self):
        return self._connection or self._connect()

    def _connect(self):
        params = self.init_data
        self._connection = boto.ec2.connect_to_region(
            self.region,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key
            )
        return self._connection

    def create_instance(self):
        self.logger.debug("Spinning up new instance")
        self._create_key()
        self._create_security_group()
        self._create_iam_roles()

        ami = self.init_data.get("instanceAmi", self.default_ami)
        instance_name = self.init_data.get("instanceName")
        instance_type = self.init_data.get("instanceType",
                self.default_instance_type)
        reservation = self.connection.run_instances(
                ami,
                key_name=self.keyname,
                security_groups=[SECURITY_GROUP_NAME],
                instance_profile_name=self.iam,
                instance_type=instance_type
                )
        instance = reservation.instances[0]
        if instance_name:
            instance.add_tag(self.instance_name_tag, instance_name)
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

    def get_s3_buckets(self):
        return ''

    def _create_iam_roles(self):
        """Test securitymonkey roles"""
        # TODO replace me
        self.logger.info("Adding iam roles")
        profile_name = "SecurityMonkey"
        self.iam = profile_name
        run_role = "SecurityMonkeyInstanceProfile"
        run_policy_name = "SecurityMonkeyLaunchPerms"
        run_policy = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "*"
    }
  ]
}
"""
        sec_role = "SecurityMonkey"
        sec_policy_name = "SecurityMonkeyReadOnly"
        sec_policy = """
        {
  "Statement": [
    {
      "Action": [
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "ec2:Describe*",
        "elasticloadbalancing:Describe*",
        "iam:List*",
        "iam:Get*",
        "route53:Get*",
        "route53:List*",
        "rds:Describe*",
        "s3:Get*",
        "s3:List*",
        "sdb:GetAttributes",
        "sdb:List*",
        "sdb:Select*",
        "ses:Get*",
        "ses:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "sqs:ReceiveMessage"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
"""

        iam = boto.connect_iam(self.access_key, self.secret_key)
        try:
            inst_profile = iam.create_instance_profile(profile_name)
        except iam.ResponseError as err:
            if err.code == 'EntityAlreadyExists':
                self.logger.info("Iam role already exists")
                return

        role = iam.create_role(run_role)
        assume_policy = {u'Version': u'2008-10-17', u'Statement': [{u'Action':
            u'sts:AssumeRole', u'Principal': {u'AWS': role.arn}, u'Effect': u'Allow', u'Sid': u''}]}
        iam.add_role_to_instance_profile(profile_name, run_role)
        iam.put_role_policy(run_role, run_policy_name, run_policy)

        iam.create_role(sec_role, json.dumps(assume_policy))
        iam.put_role_policy(sec_role, sec_policy_name, sec_policy)



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

    def get_envs(self):
        return {
                "host": self.host,
                "AWS_ACCESS_KEY_ID": self.provider.access_key,
                "AWS_SECRET_ACCESS_KEY": self.provider.secret_key
                }
    @property
    def host(self):
        return self.instance.public_dns_name

    @property
    def state(self):
        return self.instance.state

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
