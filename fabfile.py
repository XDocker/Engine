#!/usr/bin/env python
# encoding: utf-8

import os

from fabric.api import *
from fabric.contrib.console import confirm
from fabric.contrib.files import exists, upload_template
from fabric.colors import red, green, yellow, blue


env.use_ssh_config = True
env.hosts = ['xdocker']

www_user = 'sysadmin'
www_group = 'sysadmin'

git_repo = 'git@github.com:XDocker/Engine.git'


project_folder = '/home/sysadmin/projects/xdocker'


def deploy():
    local('git push')
    with cd(project_folder):
        run('git pull origin')
        run('venv/bin/pip install -r requirements.txt')
    restart_server()


def restart_server():
    run(os.path.join(project_folder, 'restart.sh'))
