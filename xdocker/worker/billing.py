import boto
import datetime
import csv
import zipfile

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from worker.exceptions import WorkerException
from models import billing_users, billing_data


class BillingException(WorkerException):
    message = "Billing exception"


class UserDoesNotExist(BillingException):
    message = "User has no billing information"




def create_billing_user(username, aws_key, aws_secret, account_id, bucket):
    try:
        bill_data = get_billing_data(aws_key, aws_secret, account_id, bucket)
    except Exception as e:
        raise BillingException()

    data = {
            "username": username,
            "active": True,
            "aws_key": aws_key,
            "aws_secret": aws_secret,
            "aws_account_id": account_id,
            "billing_bucket_name": bucket
            }
    billing_users.update({"username": username}, {"$set": data}, upsert=True)
    return True


def sync_all():
    for user in db.billing_users.find({"active": True}):
        try:
            sync_billing(user['username'])
        except Exception as e:
            continue


def sync_billing(username):
    user = billing_users.find_one({"username": username})
    if not user:
        raise UserDoesNotExist()
    data = get_billing_data(user['aws_key'], user['aws_secret'],
        user['aws_account_id'], user['billing_bucket_name'])
    names = data.next()
    for bill_data in data:
        bill_item = dict(zip(names, bill_data))
        bill_item['username'] = username
        billing_data.update(
                {"username": username, "RecordId": bill_item["RecordId"]},
                bill_item, upsert=True)


def get_billing_data(aws_key, aws_secret, account_id, bucket_name):
    s3 = boto.connect_s3(aws_key, aws_secret)
    bucket = s3.get_bucket(bucket_name)
    filename = get_filename(account_id)
    zipped_filename = "{}.zip".format(filename)
    bucket_file = bucket.get_key(zipped_filename)
    if bucket_file is None:
        raise BillingException()
    zip_fp = StringIO(bucket_file.get_contents_as_string())
    zip_file = zipfile.ZipFile(zip_fp)
    csv_obj = zip_file.open(filename)
    reader = csv.reader(csv_obj)
    return reader


def get_filename(account_id, date=None):
    if date is None:
        date = datetime.datetime.now()
    date_str = date.strftime('%Y-%m')
    return '{acc_id}-aws-billing-detailed-line-items-with-resources-and-tags-{date}.csv'.format(
        acc_id=account_id, date=date_str)
