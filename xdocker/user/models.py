import md5

from flask.ext.login import UserMixin

from ..models import db, users
from ..app_exceptions import UserDoesNotExist, InvalidPassword,\
        UserAlreadyExists
from ..utils import login_serializer



class User(UserMixin):
    def __init__(self, username):
        self.username = username
        self._user = None
        self._load_user()

    @property
    def user(self):
        return self._user or self._load_user()

    def delete(self):
        users.remove({"username": self.username})

    def _load_user(self):
        user = users.find_one({"username": self.username})
        if not user:
            raise UserDoesNotExist(self)
        self._user = user
        return user

    def get_auth_token(self):
        data = (self.username, self.user['password'])
        return login_serializer.dumps(data)

    @staticmethod
    def hash_pass(passwd):
        salted = passwd
        return md5.new(salted).hexdigest()

    def verify(self, passwd, is_hash=False):
        if not is_hash:
            hashed = self.hash_pass(passwd)
        else:
            hashed = passwd
        if hashed == self.user['password']:
            return True
        raise InvalidPassword(self)

    def _get_update_dict(self):
        return {"_id": self.user['_id']}

    def update(self, data):
        users.update(self._get_update_dict(), {"$set": data})
        self._load_user()

    def add_accountId(self, account, service_name):
        users.update(self._get_update_dict(),
                {"$addToSet": {service_name: account}}
                )

    def check_accountId(self, account, service_name):
        return account in self.user.get(service_name, [])

    @classmethod
    def create(cls, username, password, **kwargs):
        data = kwargs
        try:
            user = cls(username)
        except UserDoesNotExist:
            pass
        else:
            raise UserAlreadyExists(user)
        data['username'] = username
        data['password'] = cls.hash_pass(password)
        users.insert(data)
        return cls(username)

    def add_job(self, job_id):
        users.update(self._get_update_dict(),
                {"$push": {"jobs": job_id}}
                )

    @property
    def jobs(self):
        return self.user.get('jobs', [])

    @classmethod
    def get(cls, username):
        try:
            return cls(username)
        except UserDoesNotExist:
            return None
