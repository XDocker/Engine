#!/usr/bin/env python
# encoding: utf-8

import os

from fabric.api import *
from fabric.contrib.console import confirm
from fabric.contrib.files import exists, upload_template
from fabric.colors import red, green, yellow, blue


env.use_ssh_config = True
if not env.hosts:
    env.hosts = ['xdocker']

www_user = 'sysadmin'
www_group = 'sysadmin'

git_repo = 'git@github.com:XDocker/Engine.git'
default_branch = 'develop'


project_folder = '/home/sysadmin/projects/xdocker'

apt_apps = (
        'python-pip',
        'python-virtualenv',
        'mongodb',
        'redis-server',
        'supervisor',
        'nginx',
        'git',
        'python-dev'
        )

pip_apps = (
        'gunicorn',
        )



def create(branch):
    if exists(project_folder):
        if not confirm(yellow(
            "Remote folder %s exists. This will overwrite all contents.\
            Continue?" % project_folder),
            False):
            return
        sudo('rm -r %s' % project_folder)
    sudo('aptitude install {}'.format(' '.join(apt_apps)))
    run('mkdir -p {}'.format(project_folder))
    with cd(project_folder):
        run('git clone -b {} {} .'.format(branch, git_repo))
        run('virtualenv venv')
        run('./venv/bin/pip install {}'.format(' '.join(pip_apps)))
        run('mkdir logs')
    deploy(branch)


def deploy(branch=default_branch):
    if branch == default_branch:
        local('git push')
    with cd(project_folder):
        run('git pull origin')
        run('venv/bin/pip install -r requirements.txt')
    restart_server()


def restart_server():
    run(os.path.join(project_folder, 'restart.sh'))
