import pymongo
from config import MONGO_DBNAME

db = pymongo.MongoClient()[MONGO_DBNAME]

billing_users = db.billing_users
billing_data = db.billing_data

billing_data.ensure_index("username")
billing_data.ensure_index([("username", 1), ("RecordId", 1)])

users = db.users
