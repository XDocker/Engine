import os.path
import time
import zope.interface
import json

import boto
import boto.ec2

from .base import IProvider, MixinProvider, IInstance, MixinInstance

import logging

from ...utils import braced_param

from ..worker_exceptions import InstanceDoesNotExist, InstanceException, \
        DeployException, UnauthorizedKeyError, KeyNotSaved, PermissionError
from ...config import USER_DIRECTORY, SSH_PORT, HTTPS_PORT, HTTP_PORT, \
        DOCKER_PORT, SECURITY_GROUP_NAME


class AmazonProvider(MixinProvider):
    zope.interface.implements(IProvider)

    provider_name = "amazon aws"

    cidr = '0.0.0.0/0'
    default_region = 'us-west-2'
    default_ami = 'ami-2d9add1d'
    default_instance_type = 't1.micro'
    default_security_group_name = SECURITY_GROUP_NAME

    instance_name_tag = 'Name'

    def __init__(self, params, **kwargs):
        self.region = params.get('instanceRegion', self.default_region)
        self.cidrUI = params.get('ipUI')
        if self.cidrUI:
            self.cidrUI += '/32'
        self.billing_bucket = params.get('billingBucket')

        super(AmazonProvider, self).__init__(params, **kwargs)

        self._connection = None
        self.iam = None
        self.security_group_name = self._make_security_group_name()
        self.sg_ports = []
        self._set_sgroup_ports()

    def _set_sgroup_ports(self):
        self.sg_ports = [(port, self.cidr) for port in
                self.init_data.get('sgPorts', [])]
        self._add_default_sgroup_ports()

    def _add_default_sgroup_ports(self):
        if self.cidrUI:
            self.sg_ports.append((DOCKER_PORT, self.cidrUI))
        self.sg_ports.append((SSH_PORT, self.cidr))

    def _make_security_group_name(self):
        return self.init_data.get('instanceSecurityGroup',
                self.default_security_group_name
                )

    def _make_keyname(self):
        default_keyname = super(AmazonProvider, self)._make_keyname()
        if 'keyname' in self.init_data:
            return self.init_data['keyname']
        else:
            return '{}_{}'.format(default_keyname, self.region)

    @property
    def connection(self):
        return self._connection or self._connect()


    def get_creds(self):
        return (self.access_key, self.secret_key)

    def _process_creds(self):
        self.access_key = self.decrypt_key(self.init_data.get('apiKey'))
        self.secret_key = self.decrypt_key(self.init_data.get('secretKey'))

    def _connect(self):
        self._connection = boto.ec2.connect_to_region(
            self.region,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key
            )
        self._test_connection(self._connection)
        return self._connection

    def _test_connection(self, conn):
        try:
            conn.get_only_instances()
        except conn.ResponseError as conn_err:
            if conn_err.code == 'AuthFailure':
                raise UnauthorizedKeyError()
            raise


    def create_instance(self):
        self.logger.info("Spinning up new instance")
        try:
            self._create_key()
            self._create_security_group()
            self._create_iam_roles()
        except self.connection.ResponseError as conn_err:
            if conn_err.code == 'UnauthorizedOperation':
                raise PermissionError()
            raise

        ami = self.init_data.get("instanceAmi", self.default_ami)
        instance_name = self.init_data.get("instanceName")
        instance_type = self.init_data.get("instanceType",
                self.default_instance_type)
        try:
            reservation = self.connection.run_instances(
                ami,
                key_name=self.keyname,
                security_groups=[self.security_group_name],
                instance_profile_name=self.iam,
                instance_type=instance_type
                )
        except self.connection.ResponseError as conn_err:
            if conn_err.code == 'UnauthorizedOperation':
                raise PermissionError()
            raise
        instance = reservation.instances[0]
        if instance_name:
            instance.add_tag(self.instance_name_tag, instance_name)
        status = instance.update()
        self.logger.info("Initializing - AMI image {}".format(ami))
        self.logger.debug("Waiting for instance to start")
        while status == 'pending':
            time.sleep(3)
            status = instance.update()

        instance = self.get_instance(instance.id)
        self.logger.info("New aws instance launched: {}".format(instance))
        return instance

    def get_instance(self, instance_id):
        return AmazonInstance(self, instance_id)

    def get_s3_buckets(self):
        return ''

    def _create_iam_roles(self):
        """Test securitymonkey roles"""
        if not 'amazonIAM' in self.init_data:
            return
        rules = self.init_data['amazonIAM']
        self.logger.info("Adding iam roles")
        iam = boto.connect_iam(self.access_key, self.secret_key)
        profile_name = None
        added_rules = {}
        for rule in rules:
            assume_policy = rule.get('assumePolicy')
            instance_profile = rule.get('instanceProfile')
            rule_name = rule['ruleName']
            if assume_policy:
                var_param = braced_param.search(assume_policy)
                if var_param:
                    assumed_rule = var_param.group(1)
                    if not assumed_rule in added_rules:
                        self.logger.error(
                                "No such rule {} from assume policy".format(
                                    assumed_rule))
                        raise DeployException()
                    rule_arn = added_rules[assumed_rule]
                    assume_policy = assume_policy.replace(var_param.group(0),
                            rule_arn)
                    assume_policy = json.dumps(json.loads(assume_policy))
            try:
                role = iam.create_role(rule_name, assume_policy)
            except iam.ResponseError as err:
                if err.code == 'EntityAlreadyExists':
                    role = iam.get_role(rule_name)
                else:
                    raise
            else:
                iam.put_role_policy(rule_name, rule['policyName'],
                    rule['policy'])
            added_rules[rule_name] = role.arn
            if instance_profile:
                try:
                    inst_profile = iam.create_instance_profile(instance_profile)
                except iam.ResponseError as err:
                    if err.code == 'EntityAlreadyExists':
                        pass
                    else:
                        raise
                profile_name = instance_profile
                try:
                    iam.add_role_to_instance_profile(instance_profile,
                            rule_name)
                except iam.ResponseError as err:
                    pass

        self.iam = profile_name

    def _create_security_group(self):
        self.logger.info("Processing Job id - Using / Creating security group {}".format(
            self.security_group_name))
        try:
            group = self.connection.get_all_security_groups(groupnames=[self.security_group_name])[0]
        except self.connection.ResponseError, e:
            if e.code == 'InvalidGroup.NotFound':
                # create new group
                self.logger.info("Create new amazon security group {}".format(
                    self.security_group_name))
                group = self.connection.create_security_group(self.security_group_name,
                        "Xdocker security group")
            else:
                self.logger.error(
                    "Could not create the security group {}".format(e.code)
                    )
                raise

        for port, cidr in self.sg_ports:
            try:
                group.authorize('tcp', port, port, cidr)
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
        self.logger.info(
                "Processing Job id - Using / Creating Keypair /Name {}".format(
                    self.keyname)
                )
        try:
            key = self.connection.get_all_key_pairs(keynames=[self.keyname])[0]
            if not os.path.exists(self._get_key_path()):
                raise KeyNotSaved()
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
                "AWS_SECRET_ACCESS_KEY": self.provider.secret_key,
                "BILLING_BUCKET": self.provider.billing_bucket
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
