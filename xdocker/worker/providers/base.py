#!/usr/bin/env python
# encoding: utf-8

import os
import logging

from zope.interface import Interface, Attribute
from fabric.context_managers import settings
from rq import get_current_job

from utils import decrypt_key, get_user_directory
from config import KEY_EXTENSION, KEY_NAME, MAX_INSTALL_RETRY, SECURITY_GROUP_NAME
from worker.exceptions import KeyDoesNotExist


class IProvider(Interface):
    provider_name = Attribute("""Provider name""")

    def create_instance(self, params):
        """Create instance using given params"""

    def get_instance(self, instance_id):
        """Return instance with given id"""

    def get_key(self):
        """Return key"""


class IInstance(Interface):
    host = Attribute("""Instance public dns host""")
    user = Attribute("""User to connect with to instance""")

    def start(self):
        """Start instance"""

    def stop(self):
        """Stop instance"""

    def restart(self):
        """Restart instance"""

    def terminate(self):
        """Terminate instance"""


registry = {}


class MixinProvider(object):

    default_keyname = KEY_NAME
    default_security_group_name = SECURITY_GROUP_NAME

    def __init__(self, params, logger=None):
        self.username = params['username']
        self.user_directory = get_user_directory(self.username)
        self.logger = logger or logging.getLogger(self.username)
        self.init_data = params
        self.keyname = self._make_keyname()
        self.security_group_name = self._make_security_group_name()

    def _make_security_group_name(self):
        return self.init_data.get('security_group_name',
                'xdocker_{}_{}'.format(
                    self.default_security_group_name, self.username
                    )
                )

    def _make_keyname(self):
        return self.init_data.get('keyname',
                'xdocker_{}_{}'.format(
                    self.default_keyname, self.username
                    )
                )

    def _get_key_path(self):
        return os.path.join(self.user_directory, "{}{}".format(self.keyname,
            KEY_EXTENSION))

    def get_key(self):
        key_path = self._get_key_path()
        if not os.path.exists(key_path):
            raise KeyDoesNotExist()
        with open(key_path) as fp:
            key = fp.read()
        return key

    def save_key(self, key):
        key_path = self._get_key_path()
        with open(key_path, 'w') as fp:
            fp.write(key)



class MixinInstance(object):
    def __init__(self, provider, instance_id):
        self.provider = provider
        self.instance_id = instance_id
        self.instance = None
        self.logger = self.provider.logger

    def __unicode__(self):
        return "Instance: {}".format(self.instance_id)

    def __repr__(self):
        return unicode(self)

    def ssh(self):
        return settings(key_filename=self.provider._get_key_path(),
                host_string=self.host, user=self.user,
                connection_attempts=MAX_INSTALL_RETRY)

    def restart(self):
        self.logger.info("Restarting the instance: {}".format(self))
        self.stop()
        self.start()
