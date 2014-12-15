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
    status_code = 404


class UserAlreadyExists(UserException):
    message = "User already exists"
    status_code = 409


class InvalidPassword(UserException):
    message = "Invalid password"
    status_code = 401


class PermissionDenied(UserException):
    message = 'Permission denied'
    status_code = 403


class AccountPermissionDenied(PermissionDenied):
    message = "AccountId access denied"

class JobWorkerException(AppException):
    message = ''


class RequestException(AppException):
    pass

class TokenExpired(RequestException):
    message = "Your token has expired"
    status_code = 401

class BadToken(RequestException):
    message = "Bad token"
    status_code = 401


class BadInput(RequestException):
    status_code = 422
