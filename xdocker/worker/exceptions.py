class WorkerException(Exception):
    message = "Worker error"


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


class KeyDoesNotExist(WorkerException):
    message = "Key does not exist for user"
