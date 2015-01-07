import pymongo
from ..config import MONGO_DBNAME, MONGO_CONN

db = pymongo.MongoClient(MONGO_CONN)[MONGO_DBNAME]

billing_users = db.billing_users
billing_data = db.billing_data

billing_data.ensure_index("username")
billing_data.ensure_index([("username", 1), ("RecordId", 1)])

users = db.users
