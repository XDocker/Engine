
import os

from flask import Flask, jsonify, request

from rq import Connection, Queue
from redis import Redis


from worker import jobs


app = Flask(__name__)
app.config.from_object('config')

redis_conn = Redis()
q = Queue(connection=redis_conn)


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


class JobWorkerException(AppException):
    message = ''


class RequestException(AppException):
    pass


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


@app.route("/run", methods=["POST"])
def run_instance():
    data = check_args(
            ('cloudProvider', 'apiKey', 'secretKey', 'packageName', 'username')
            )
    job = q.enqueue_call(jobs.deploy, args=(data,), timeout=300,
            result_ttl=86400)
    return make_response(job_id=job.id)


@app.route("/instance", methods=["POST"])
def instance_action():
    data = check_args(
            ('cloudProvider', 'apiKey', 'secretKey', 'instanceAction',
            'instanceId')
        )
    job = q.enqueue_call(jobs.instance_action, args=(data,), result_ttl=6400)
    return make_response(job_id=job.id)


@app.route("/getDeploymentStatus/<job_id>")
def job_status(job_id):
    job = q.fetch_job(job_id)
    status = job.get_status()
    res_dict = {}
    if status == 'failed':
        res_dict['job_log'] = 'Logs'
    elif status == 'finished':
        status = 'Completed'
    res_dict['job_status'] = status
    res_dict['result'] = job.result
    return make_response(**res_dict)


@app.route("/uploadKey", methods=["POST"])
def upload_key():
    pass


@app.route("/downloadKey")
def download_key():
    pass

if __name__ == '__main__':
    app.run(host=app.config['APP_HOST'], port=app.config['APP_PORT'])

