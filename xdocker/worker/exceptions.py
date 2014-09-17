class WorkerException(Exception):
    message = ""


class NoSuchProvider(WorkerException):
    message = "No such provider exists"


class InstanceException(WorkerException):
    pass


class InstanceDoesNotExist(InstanceException):
    def __init__(self, instance):
        self.instance = instance.instance

    def __str__(self):
        return "{} does not exist".format(self.instance)


class KeyDoesNotExist(WorkerException):
    message = "Key does not exist for user"
