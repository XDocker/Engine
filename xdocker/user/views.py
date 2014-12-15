from flask import Blueprint
from flask.ext.login import current_user

from ..helpers import check_args, make_response
from .models import User


user = Blueprint('user', __name__)


@user.route("/authenticate", methods=["POST"])
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


@user.route("/removeUsername", methods=["POST"])
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


@user.route("/register", methods=["POST"])
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


