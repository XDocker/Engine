
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
        salted = passwd + app.secret_key
        return md5.new(salted).hexdigest()

    def verify(self, passwd, is_hash=False):
        if not is_hash:
            hashed = self.hash_pass(passwd)
        else:
            hashed = passwd
        if hashed == self.user['password']:
            return True
        return False

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
        if user.verify(data[1], is_hash=True):
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


class UserAlreadyExists(UserException):
    message = "User already exists"


class JobWorkerException(AppException):
    message = ''


class RequestException(AppException):
    pass

class TokenExpired(RequestException):
    message = "Your token has expired"

class BadToken(RequestException):
    message = "Bad token"


class BadInput(RequestException):
    status_code = 422


@app.errorhandler(AppException)
def error_handler(error):
    response = make_response(
        message=error.message,
        fail=True
        )
    response.status_code = error.status_code
    return response


def check_args(args_list):
    """Check if required args in request data"""
    data = request.get_json(force=True)
    try:
        keys = data.keys()
    except StandardError:
        raise BadInput("Missing json data")

    missing = set(args_list) - set(keys)
    if missing:
        raise BadInput("Missing args:{}".format(', '.join(missing)))
    return data


@app.route("/authenticate", methods=["POST"])
def authenticate():
    data = check_args(('username', 'password'))
    user = User(data['username'])
    if user.verify(data['password']):
        token = user.get_auth_token()
        return make_response(token=token)
    return make_response()



@app.route("/register", methods=["POST"])
def register():
    data = check_args(('username', 'password'))
    username = data.pop('username')
    passwd = data.pop('password')
    user = User.create(username, passwd, **data)
    return make_response(message='Successfully registered')


@app.route("/run", methods=["POST"])
@login_required
def run_instance():
    data = check_args(
            ('cloudProvider', 'apiKey', 'secretKey', 'packageName', 'username')
            )
    job = q.enqueue_call(jobs.deploy, args=(data,), timeout=300,
            result_ttl=86400)
    return make_response(job_id=job.id)


@app.route("/instance", methods=["POST"])
@login_required
def instance_action():
    data = check_args(
            ('cloudProvider', 'apiKey', 'secretKey', 'instanceAction',
            'instanceId')
        )
    job = q.enqueue_call(jobs.instance_action, args=(data,), result_ttl=6400)
    return make_response(job_id=job.id)


@app.route("/getDeploymentStatus/<job_id>", methods=["POST"])
@login_required
def job_status(job_id):
    res_dict = {}

    print current_user

    job = q.fetch_job(job_id)
    if job:
        status = job.get_status()
        res_dict['result'] = job.result
    else:
        status = 'Does not exist'

    if status == 'failed':
        res_dict['job_log'] = 'Logs'
    elif status == 'finished':
        status = 'Completed'
    res_dict['job_status'] = status
    return make_response(**res_dict)


@app.route("/uploadKey", methods=["POST"])
@login_required
def upload_key():
    pass


@login_required
@app.route("/downloadKey")
def download_key():
    pass

if __name__ == '__main__':
    app.run(host=app.config['APP_HOST'], port=app.config['APP_PORT'])

