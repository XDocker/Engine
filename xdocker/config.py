import os

ROOT_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), os.pardir)
DATA_DIRECTORY = os.path.join(ROOT_PATH, os.pardir, 'data')
USER_DIRECTORY = os.path.join(DATA_DIRECTORY, 'users')
LOG_DIRECTORY_NAME = 'logs'

for direc in (DATA_DIRECTORY, USER_DIRECTORY):
    if not os.path.exists(direc):
        os.mkdir(direc)

DEPS_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates','os_dependency_username.json')
# Webservice part

DEBUG = True
APP_HOST = '0.0.0.0'
APP_PORT = 5000

SECRET_KEY = "x8cWiF00CZc2kMS1YUPqfuWnyh1BkaH6wf3ICJdsYjVkkKkgFdqc"

TOKEN_EXPIRES = 12000

MONGO_DBNAME = 'xdocker'


# Worker part

SECURITY_GROUP_NAME = 'xervmon'
KEY_NAME = 'xervmon'
KEY_EXTENSION = '.pem'

STORE_LOGS = 2 # in days

MAX_INSTALL_RETRY = 3

SSH_PORT = 22
HTTP_PORT = 80
HTTPS_PORT = 443
DOCKER_PORT = 4243