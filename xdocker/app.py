import os

import logging
import logging.handlers


import bson
from flask import Flask, abort

from . import config

from .extensions import login_manager
from .helpers import make_response

from .app_exceptions import *

from .api import api
from .user import user
from .job import job


BLUEPRINTS = (
        api,
        user,
        job
        )



def create_app():
    app = Flask(__name__)
    app.config.from_object(config)
    configure_converters(app)
    configure_extensions(app)
    configure_blueprints(app)
    configure_error_handlers(app)
    configure_logging(app)
    return app



def configure_blueprints(app):
    for bp in BLUEPRINTS:
        app.register_blueprint(bp)


def configure_converters(app):
    # converter
    from werkzeug.routing import BaseConverter

    class BSONObjectIdConverter(BaseConverter):
        """A simple converter for the RESTfull URL routing system of Flask.
        .. code-block:: python
            @app.route('/<ObjectId:task_id>')
            def show_task(task_id):
                task = db.Task.get_from_id(task_id)
                return render_template('task.html', task=task)
        It checks the validate of the id and converts it into a
        :class:`bson.objectid.ObjectId` object. The converter will be
        automatically registered by the initialization of
        :class:`~flask.ext.mongokit.MongoKit` with keyword :attr:`ObjectId`.
        """

        def to_python(self, value):
            try:
                return bson.ObjectId(value)
            except bson.errors.InvalidId:
                raise abort(400)

        def to_url(self, value):
            return str(value)

    app.url_map.converters['ObjectId'] = BSONObjectIdConverter

def configure_logging(app):
    root_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), os.pardir)
    log_dir = os.path.join(root_path, 'logs')
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)
    log_handler = logging.StreamHandler()
    log_handler.setLevel(logging.INFO)
    file_handler = logging.handlers.RotatingFileHandler(os.path.join(log_dir,
                    'webs.log'))
    file_handler.setLevel(logging.DEBUG)
    app.logger.addHandler(log_handler)
    app.logger.addHandler(file_handler)


def configure_extensions(app):
    from .utils import login_serializer
    from .user import User
    import itsdangerous

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
    login_manager.init_app(app)


def configure_error_handlers(app):
    @app.errorhandler(AppException)
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
