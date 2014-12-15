from flask import Blueprint

from flask.ext.login import current_user, login_required

from ..helpers import check_args, make_response
from .helpers import  get_job_log, get_job_status
from ..app_exceptions import PermissionDenied


job = Blueprint('job', __name__)

@job.route("/getLog/<job_id>", methods=["POST"])
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
    data = check_args()
    log = get_job_log(data['username'], job_id)
    return make_response(log=log)


@job.route("/getDeploymentStatus/<job_id>", methods=["POST"])
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
    res_dict = get_job_status(job_id)
    return make_response(**res_dict)


@job.route("/getStatusOfAllDeployments", methods=["POST"])
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
            "jobs": [
                {
                    "job_id": "<job-id>",
                    "fail": true,
                    "fail_code": "BadPort",
                    "fail_message": "Wrong port: 20,",
                    "result": null,
                    "job_status": "failed"
                }
            ]
        }

    :jsonparam string token: Authentication token
    :statuscode 200: no error
    :statuscode 401: not authorized
    :>json array jobs: Statuses of user`s jobs
    :>json string jobs.job_status: Status of user`s jobs(failed, Completed, started, null)
    :>json boolean jobs.fail: whether it failed
    :>json any jobs.result: job result
    :>json string jobs.fail_code: fail code if failed
    :>json string jobs.job_id: Job id
    :>json string jobs.fail_message: fail message if failed
    """
    statuses = []
    for job_id in current_user.jobs:
        try:
            res_dict = get_job_status(job_id)
        except PermissionDenied:
            continue
        if res_dict['job_status'] is None:
            continue
        res_dict['job_id'] = job_id
        statuses.append(res_dict)
    return make_response(jobs=statuses)
