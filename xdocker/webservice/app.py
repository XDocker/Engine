
import os
import md5

import logging
import logging.handlers

from flask import Flask, jsonify, request
from flask.ext.login import LoginManager, UserMixin, current_user, \
        login_required

import itsdangerous
from itsdangerous import URLSafeTimedSerializer

from rq import Connection, Queue
from redis import Redis

from worker import jobs, billing
from worker.exceptions import WorkerException
from utils import encrypt_key, decrypt_key, get_job_log
from models import users


root_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), os.pardir)
log_dir = os.path.join(root_path, 'logs')
if not os.path.exists(log_dir):
    os.mkdir(log_dir)
app = Flask(__name__)
app.config.from_object('config')
app.debug = False

log_handler = logging.StreamHandler()
log_handler.setLevel(logging.INFO)
file_handler = logging.handlers.RotatingFileHandler(os.path.join(log_dir,
                'webs.log'))
file_handler.setLevel(logging.DEBUG)
app.logger.addHandler(log_handler)
app.logger.addHandler(file_handler)


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
        users.remove({"username": self.username})

    def _load_user(self):
        user = users.find_one({"username": self.username})
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

    def _get_update_dict(self):
        return {"_id": self.user['_id']}

    def update(self, data):
        users.update(self._get_update_dict(), {"$set": data})
        self._load_user()

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
        users.insert(data)
        return cls(username)

    def add_job(self, job_id):
        users.update(self._get_update_dict(),
                {"$push": {"jobs": job_id}}
                )

    @property
    def jobs(self):
        return self.user.get('jobs', [])

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


class PermissionDenied(UserException):
    message = 'Permission denied'
    status_code = 403


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
            "status": "OK",
            "message": "Username removed successfully"
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
            "sgPorts": [80, 443],
            "apiKey": "<api key>",
            "cloudProvider": "amazon aws",
            "instanceType": "m3.medium",
            "instanceRegion": "us-east-1",
            "instanceAmi": "ami-8997afe0",
            "amazonIAM": [
              {
                  "ruleName": "SecurityMonkeyInstanceProfile",
                  "policyName": "SecurityMonkeyLaunchPerms",
                  "instanceProfile": "SecurityMonkey",
                  "policy": "<json policy>"
              }
            ]
            "OS": "CentOS 6.5"
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
    :jsonparam string instanceSecurityGroup: Name of amazon security group to use (optional)
    :jsonparam string OS: Type of the OS
    :jsonparam string ipUI: add to ACL list
    :jsonparam list sgPorts: List of security group ports to expose
    :jsonparam string instanceName: Amazon instance tag with key Name (optional)
    :jsonparam list amazonIAM: list of Amazon IAM rules \
            order of rules is important in some cases
    :jsonparam array amazonIAM.rule: array iam rule
    :jsonparam string amazomIAM.rule.ruleName: name of the rule
    :jsonparam string amazomIAM.rule.policyName: name of the policy
    :jsonparam string amazomIAM.rule.policy: rule policy
    :jsonparam string amazomIAM.rule.instanceProfile: name of profile. \
            The instance starts with this rule(optional)
    :jsonparam string amazomIAM.rule.assumePolicy: assume policy \
            for the rule(optional). It accepts braced rule name \
            e.g. {SecMonkey} that will be replaced with rule's arn
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
            ('cloudProvider', 'apiKey', 'secretKey', 'packageName', 'OS',
            'sgPorts')
            )
    job = q.enqueue_call(jobs.deploy, args=(data,), timeout=1200,
            result_ttl=86400)
    current_user.add_job(job.id)
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
            "instanceId": "i-f7657ffa",
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
    :jsonparam string instanceId: Instance id
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
        if not job.id in current_user.jobs:
            raise PermissionDenied(current_user)
        status = job.get_status()
        res_dict['result'] = job.result
    else:
        status = 'Does not exist'

    if status == 'failed':
        res_dict['job_log'] = get_job_log(current_user.username, job_id)
        res_dict['fail_code'] = job.meta.get('exc_code', '')
        res_dict['fail_message'] = job.meta.get('exc_message', '')
        res_dict['fail'] = True
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


@app.route("/getStatusOfAllDeployments", methods=["POST"])
@login_required
def get_all_deployments():
    """Get job ids

    **Example request**

    .. sourcecode:: http

        POST /getStatusOfAllDeployments HTTP/1.1
        {
            "token": "<token>",
        }

    **Example response**

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Type: application/json

        {
            "status": "OK",
            "jobs": {
                "<job_id>": "<status>"
                ...
            }
        }

    :jsonparam string token: Authentication token
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json array jobs: Statuses of user`s jobs
    """
    statuses = {}
    for job_id in current_user.jobs:
        job = q.fetch_job(job_id)
        if not job:
            continue
        statuses[job_id] = job.get_status()
    return make_response(jobs=statuses)


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
            "keyName": "<key>",
            "key": "<key data>"
        }

    :jsonparam string token: Authentication token
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json string key: encrypted security key
    """
    data = check_args(('cloudProvider', ))
    provider = jobs.init_provider(data, True)
    key = encrypt_key(provider.get_key())
    return make_response(keyName=provider.keyname, key=key)


@app.route("/sourceBillingData", methods=["POST"])
@login_required
def sourceBillingData():
    """SourceBillingData

    **Example request**

    .. sourcecode:: http

        POST /sourceBillingData HTTP/1.1
        {
            "token": "<token>",
            "cloudProvider": "amazon aws",
            "apiKey": "<api key>",
            "secretKey": "<api secret>",
            "bucketName": "<Optional billing bucket>"
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

    :jsonparam string cloudProvider: cloud provider name
    :jsonparam string apiKey: Provider`s api key
    :jsonparam string secretKey: Provider`s secret key
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json string job_id: Deployment job id
    """
    data = check_args(
            ('cloudProvider', 'apiKey', 'secretKey')
            )
    job = q.enqueue_call(jobs.sourceBillingData, args=(data,), timeout=1200,
            result_ttl=86400)
    current_user.add_job(job.id)
    return make_response(job_id=job.id)


@app.route("/create_billing", methods=["POST"])
@login_required
def create_billing():
    """Create billing account to sync aws billing data
    **Example request**

    .. sourcecode:: http

        POST /create_billing HTTP/1.1
        {
            "token": "<token>",
            "apiKey": "<api key>",
            "secretKey": "<api secret>",
            "bucketName": "<billing bucket>"
            "accountId": "<aws account id>"
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

    :jsonparam string cloudProvider: cloud provider name
    :jsonparam string apiKey: Provider`s api key
    :jsonparam string secretKey: Provider`s secret key
    :jsonparam string accountId: User`s account in aws
    :jsonparam string billingBucket: S3 bucket with billing data
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json string job_id: Deployment job id
    """
    data = check_args(
            ('apiKey', 'secretKey', 'accountId', 'billingBucket')
            )
    job = q.enqueue_call(billing.create_billing_user, args=(
        data['username'], data['apiKey'], data['secretKey'], data['accountId'],
        data['billingBucket']
        ), timeout=1200, result_ttl=86400)
    current_user.add_job(job.id)
    return make_response(job_id=job.id)


if __name__ == '__main__':
    app.run(host=app.config['APP_HOST'], port=app.config['APP_PORT'])

