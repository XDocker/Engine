from flask import Blueprint, current_app
from flask.ext.login import current_user, login_required

from ..helpers import check_args, make_response
from ..utils import decrypt_key, encrypt_key

from ..tasks import jobs


api = Blueprint('api', __name__)


@api.route("/run", methods=["POST"])
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
    :jsonparam list dockerParams.ports: list of ports in either format \
            [443, 500] or [{"in": 443, "out": 443}]
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
    job = jobs.deploy.apply_async(args=(data,))
    current_user.add_job(job.id)
    return make_response(job_id=job.id)


@api.route("/instance", methods=["POST"])
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
    job = jobs.instance_action.apply_async(args=(data,))
    return make_response(job_id=job.id)




@api.route("/uploadKey", methods=["POST"])
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
    key = decrypt_key(data['key'], data['username'])
    provider.save_key(key)
    return make_response()


@login_required
@api.route("/downloadKey", methods=["POST"])
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
    key = encrypt_key(provider.get_key(), data['username'])
    return make_response(keyName=provider.keyname, key=key)
