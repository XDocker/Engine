
import os
import md5

from flask import Flask, jsonify, request
from flask.ext.login import LoginManager, UserMixin, current_user, \
        login_required
from flask.ext.pymongo import PyMongo

import itsdangerous
from itsdangerous import URLSafeTimedSerializer

from rq import Connection, Queue
from redis import Redis

from worker import jobs
from worker.exceptions import WorkerException
from utils import encrypt_key, decrypt_key, get_job_log


app = Flask(__name__)
app.config.from_object('config')

mongo = PyMongo(app)

redis_conn = Redis()
q = Queue(connection=redis_conn)

login_serializer = URLSafeTimedSerializer(app.secret_key)
login_manager = LoginManager()
login_manager.init_app(app)



class User(UserMixin):
    def __init__(self, username):
        self.username = username
        self._user = None
        self._load_user()

    @property
    def user(self):
        return self._user or self._load_user()

    def delete(self):
        mongo.db.users.remove({"username": self.username})

    def _load_user(self):
        user = mongo.db.users.find_one({"username": self.username})
        if not user:
            raise UserDoesNotExist(self)
        self._user = user
        return user

    def get_auth_token(self):
        data = (self.username, self.user['password'])
        return login_serializer.dumps(data)

    @staticmethod
    def hash_pass(passwd):
        salted = passwd
        return md5.new(salted).hexdigest()

    def verify(self, passwd, is_hash=False):
        if not is_hash:
            hashed = self.hash_pass(passwd)
        else:
            hashed = passwd
        if hashed == self.user['password']:
            return True
        raise InvalidPassword(self)

    @classmethod
    def create(cls, username, password, **kwargs):
        data = kwargs
        try:
            user = cls(username)
        except UserDoesNotExist:
            pass
        else:
            raise UserAlreadyExists(user)
        data['username'] = username
        data['password'] = cls.hash_pass(password)
        mongo.db.users.insert(data)
        return cls(username)

    @classmethod
    def get(cls, username):
        try:
            return cls(username)
        except UserDoesNotExist:
            return None


@login_manager.request_loader
def load_user_from_request(request):
    try:
        json_data = request.get_json(force=True)
    except AttributeError:
        json_data = {}
    token = json_data.get('token')

    if token:
        try:
            data = login_serializer.loads(token, max_age=app.config['TOKEN_EXPIRES'])
        except itsdangerous.SignatureExpired:
            raise TokenExpired()
        except itsdangerous.BadSignature:
            raise BadToken()
        user = User(data[0])
        try:
            user.verify(data[1], is_hash=True)
        except InvalidPassword:
            pass
        else:
            return user
    return None



def make_response(**kwargs):
    fail = kwargs.pop('fail', False)
    if fail:
        kwargs['status'] = 'error'
    else:
        kwargs['status'] = 'OK'
    return jsonify(**kwargs)


class AppException(Exception):
    status_code = 200
    message = ''

    def __init__(self, message=None):
        if message:
            self.message = message

class UserException(AppException):
    def __init__(self, user, message=None):
        self.user = user
        if message:
            self.message = message


class UserDoesNotExist(UserException):
    message = "User does not exist"
    status_code = 404


class UserAlreadyExists(UserException):
    message = "User already exists"
    status_code = 409


class InvalidPassword(UserException):
    message = "Invalid password"
    status_code = 401


class JobWorkerException(AppException):
    message = ''


class RequestException(AppException):
    pass

class TokenExpired(RequestException):
    message = "Your token has expired"
    status_code = 401

class BadToken(RequestException):
    message = "Bad token"
    status_code = 401


class BadInput(RequestException):
    status_code = 422


@app.errorhandler(AppException)
@app.errorhandler(WorkerException)
def error_handler(error):
    response = make_response(
        message=error.message,
        fail=True
        )
    try:
        response.status_code = error.status_code
    except AttributeError:
        pass
    return response


def check_args(args_list):
    """Check if required args in request data"""
    data = request.get_json(force=True)
    try:
        keys = data.keys()
    except StandardError:
        raise BadInput("Missing json data")
    if current_user.is_authenticated():
        data['username'] = current_user.username

    missing = set(args_list) - set(keys)
    if missing:
        raise BadInput("Missing args:{}".format(', '.join(missing)))
    return data


@app.route("/authenticate", methods=["POST"])
def authenticate():
    """Authenticate method


    **Example request**

    .. sourcecode:: http

        POST /authenticate HTTP/1.1
        {
            "password": "test",
            "username": "test"
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Encoding: gzip
        Content-Type: application/json
        Server: nginx/1.1.19
        Vary: Accept-Encoding

        {
            "status": "OK",
            "token": "<token>"
        }

    :jsonparam string username: Username to authenticate
    :jsonparam string password: Password for the user
    :statuscode 200: no error
    :statuscode 404: user does not exist
    :>json string token: Token to use
    """
    data = check_args(('username', 'password'))
    user = User(data['username'])
    user.verify(data['password'], is_hash=True)
    token = user.get_auth_token()
    return make_response(token=token)


@app.route("/removeUsername", methods=["POST"])
def remove_user():
    """Remove user


    **Example request**

    .. sourcecode:: http

        POST /removeUsername HTTP/1.1
        {
            "token": "<token>"
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Encoding: gzip
        Content-Type: application/json
        Server: nginx/1.1.19
        Vary: Accept-Encoding

        {
            "status": "Username removed successfully",
        }

    :jsonparam string token: Authentication token
    :statuscode 200: no error
    """
    current_user.delete()
    return make_response(message='Username removed successfully')


@app.route("/register", methods=["POST"])
def register():
    """Register method


    **Example request**

    .. sourcecode:: http

        POST /register HTTP/1.1
        {
            "password": "test",
            "username": "test"
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Encoding: gzip
        Content-Type: application/json
        Server: nginx/1.1.19
        Vary: Accept-Encoding

        {
            "status": "OK",
        }

    :jsonparam string username: Username to register
    :jsonparam string password: Password for the user
    :statuscode 200: no error
    :statuscode 409: user already exists
    """
    data = check_args(('username', 'password'))
    username = data.pop('username')
    passwd = data.pop('password')
    user = User.create(username, passwd, **data)
    return make_response(message='Successfully registered')


@app.route("/run", methods=["POST"])
@login_required
def run_instance():
    """Run instance and deploy dockerhub package

    **Example request**

    .. sourcecode:: http

        POST /run HTTP/1.1
        {
            "token": "<token>",
            "secretKey": "<api secret>",
            "packageName": "xdocker/securitymonkey",
            "dockerParams": {"ports": [443, 5000], "env": {}, "tag": "v1",
            "cmd": "/home/ubuntu/securitymonkey.sh"},
            "apiKey": "<api key>",
            "cloudProvider": "amazon aws"
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Encoding: gzip
        Content-Type: application/json
        Server: nginx/1.1.19
        Vary: Accept-Encoding

        {
            "status": "OK",
            "job_id": "<job id>"
        }

    :jsonparam string token: Authentication token
    :jsonparam string cloudProvider: cloud provider name
    :jsonparam string apiKey: Provider`s api key
    :jsonparam string instanceId: Instance id to use for docker deployment(optional)
    :jsonparam string instanceRegion: Region to create instance in (optional)
    :jsonparam string instanceAmi: Ami to use for amazon instance(optional)
    :jsonparam string instanceType: Type of the amazon instance (optional)
    :jsonparam string secretKey: Provider`s secret key
    :jsonparam string packageName: dockerhub package name
    :jsonparam array dockerParams: package params for docker to start
    :jsonparam list dockerParams.ports: list of ports
    :jsonparam string dockerParams.tag: docker package tag
    :jsonparam string dockerParams.cmd: docker command to run
    :jsonparam array dockerParams.env: environment variables to pass to docker.  Some values can be templated using brackets e.g. {host} converts to instance`s public dns
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json string job_id: Deployment job id
    """
    data = check_args(
            ('cloudProvider', 'apiKey', 'secretKey', 'packageName', 'username')
            )
    job = q.enqueue_call(jobs.deploy, args=(data,), timeout=1200,
            result_ttl=86400)
    return make_response(job_id=job.id)


@app.route("/instance", methods=["POST"])
@login_required
def instance_action():
    """Perform action on instance


    **Example request**

    .. sourcecode:: http

        POST /instance HTTP/1.1
        {
            "token": "<token>",
            "secretKey": "<api secret>",
            "apiKey": "<api key>",
            "instanceAction": "stop",
            "cloudProvider": "amazon aws"
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Encoding: gzip
        Content-Type: application/json
        Server: nginx/1.1.19
        Vary: Accept-Encoding

        {
            "status": "OK",
            "job_id": "<job id>"
        }

    :jsonparam string token: Authentication token
    :jsonparam string cloudProvider: cloud provider name
    :jsonparam string apiKey: Provider`s api key
    :jsonparam string secretKey: Provider`s secret key
    :jsonparam string instanceAction: Action to perform on instance(start, stop, restart, terminate)
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json string job_id: Instance job id
    """
    data = check_args(
            ('cloudProvider', 'apiKey', 'secretKey', 'instanceAction',
            'instanceId')
        )
    job = q.enqueue_call(jobs.instance_action, args=(data,), result_ttl=6400)
    return make_response(job_id=job.id)


@app.route("/getDeploymentStatus/<job_id>", methods=["POST"])
@login_required
def job_status(job_id):
    """Get job status

    **Example request**

    .. sourcecode:: http

        POST /getDeploymentStatus/<job_id> HTTP/1.1
        {
            "token": "<token>"
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Encoding: gzip
        Content-Type: application/json
        Server: nginx/1.1.19
        Vary: Accept-Encoding

        {
            "status": "OK",
            "job_status": "Completed"
        }

    :jsonparam string token: Authentication token
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json string job_status: Job status
    """
    res_dict = {}

    job = q.fetch_job(job_id)
    if job:
        status = job.get_status()
        res_dict['result'] = job.result
    else:
        status = 'Does not exist'

    if status == 'failed':
        res_dict['job_log'] = get_job_log(current_user.username, job_id)
    elif status == 'finished':
        status = 'Completed'
    res_dict['job_status'] = status
    return make_response(**res_dict)


@app.route("/getLog/<job_id>", methods=["POST"])
@login_required
def get_log(job_id):
    """Get log for job


    **Example request**

    .. sourcecode:: http

        POST /getLog/<job_id> HTTP/1.1
        {
            "token": "<token>",
            "line_num": 10
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Encoding: gzip
        Content-Type: application/json
        Server: nginx/1.1.19
        Vary: Accept-Encoding

        {
            "status": "OK",
            "log": "<log lines>"
        }

    :jsonparam string token: Authentication token
    :jsonparam integer line_num: Number of log lines to return(max 100, 10 default)
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json string log: Last logs
    """
    data = check_args(tuple())
    log = get_job_log(data['username'], job_id)
    return make_response(log=log)


@app.route("/uploadKey", methods=["POST"])
@login_required
def upload_key():
    """Upload security key


    **Example request**

    .. sourcecode:: http

        POST /uploadKey HTTP/1.1
        {
            "token": "<token>",
            "key": "<key">,
            "cloudProvider": "amazon aws"
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Encoding: gzip
        Content-Type: application/json
        Server: nginx/1.1.19
        Vary: Accept-Encoding

        {
            "status": "OK",
        }

    :jsonparam string token: Authentication token
    :jsonparam string key: Encrypted security key
    :jsonparam string cloudProvider: cloud provider name
    :statuscode 200: no error
    :statuscode 401: not authorized
    """
    data = check_args(('cloudProvider', 'key'))
    provider = jobs.init_provider(data, True)
    key = decrypt_key(data['key'])
    provider.save_key(key)
    return make_response()


@login_required
@app.route("/downloadKey", methods=["POST"])
def download_key():
    """Download security key


    **Example request**

    .. sourcecode:: http

        POST /downloadKey HTTP/1.1
        {
            "token": "<token>",
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Encoding: gzip
        Content-Type: application/json
        Server: nginx/1.1.19
        Vary: Accept-Encoding

        {
            "status": "OK",
            "key": "<key>"
        }

    :jsonparam string token: Authentication token
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json string key: encrypted security key
    """
    data = check_args(('cloudProvider', ))
    provider = jobs.init_provider(data, True)
    key = encrypt_key(provider.get_key())
    return make_response(key=key)


if __name__ == '__main__':
    app.run(host=app.config['APP_HOST'], port=app.config['APP_PORT'])

