class WorkerException(Exception):
    message = "Worker error"
    code = None


class DeployException(WorkerException):
    message = "Could not deploy"


class NoSuchProvider(WorkerException):
    message = "No such provider exists"


class InstanceCreateException(WorkerException):
    message = "Could not create instance"


class InstanceException(WorkerException):
    pass


class InstanceDoesNotExist(InstanceException):
    def __init__(self, instance):
        self.instance = instance.instance

    def __str__(self):
        return "{} does not exist".format(self.instance)


class ConnectionError(WorkerException):
    message = "Connection error"


class UnauthorizedKeyError(ConnectionError):
    message = "Cannot connect using given key"
    code = "BadKey"


class KeyNotSaved(WorkerException):
    message = "Key exists but not saved"
    code = "KeyNotSaved"


class KeyDoesNotExist(WorkerException):
    message = "Key does not exist for user"
