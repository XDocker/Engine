import datetime
try:
    import simplejson as json
except ImportError:
    try:
        import json
    except ImportError:
        raise ImportError

from bson import ObjectId, DBRef

from flask import Response, request
from flask.ext.login import current_user

from .utils import datetime_to_timestamp
from .app_exceptions import BadInput, AccountPermissionDenied, \
        PermissionDenied

class MongoJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return unicode(obj)
        elif isinstance(obj, DBRef):
            return unicode(obj.id)
        elif isinstance(obj, (datetime.datetime, datetime.date)):
            return datetime_to_timestamp(obj)
        return json.JSONEncoder.default(self, obj)


def jsonify_resp(*args, **kwargs):
    """ jsonify with support for MongoDB ObjectId
    """
    return Response(json.dumps(dict(*args, **kwargs), cls=MongoJsonEncoder), mimetype='application/json')


def make_response(**kwargs):
    fail = kwargs.pop('fail', False)
    if fail:
        kwargs['status'] = 'error'
    else:
        kwargs['status'] = 'OK'
    return jsonify_resp(**kwargs)


def check_args(args_list=None):
    """Check if required args in request data"""
    data = request.get_json(force=True)
    try:
        keys = data.keys()
    except StandardError:
        raise BadInput("Missing json data")
    if current_user.is_authenticated():
        data['username'] = current_user.username
    if args_list is not None:
        missing = set(args_list) - set(keys)
        if missing:
            raise BadInput("Missing args:{}".format(', '.join(missing)))
    return data

def user_account_from_args(service):
    data = check_args(('accountId', ))
    if not current_user.check_accountId(data['accountId'], service):
        raise AccountPermissionDenied(current_user)
    return {"username": data['username'], "accountId": data['accountId']}

