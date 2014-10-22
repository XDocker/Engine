import os
import re
import logging

from Crypto.Cipher import AES
import base64
import md5

from config import USER_DIRECTORY, LOG_DIRECTORY_NAME, ENCRYPTION_KEY
from rq import get_current_job



LOGGER_HANDLER_NAME = "xdocker"

def init_encryptor(username):
    username = get_username(username)
    AES.key_size = 128
    iv = ENCRYPTION_KEY
    key = md5.md5(username).hexdigest()
    encr_obj = AES.new(key=key, IV=iv, mode=AES.MODE_CBC)
    return encr_obj


def pad_string(string):
    return string + b'\0' * (AES.block_size - len(string) % AES.block_size)


def decrypt_key(key, username=None):
    encryptor = init_encryptor(username)
    key = base64.b64decode(key)
    key = encryptor.decrypt(key)
    return key.strip().strip('\0')


def encrypt_key(key, username=None):
    encryptor = init_encryptor(username)
    padded_key = pad_string(key)
    encrypted_key = encryptor.encrypt(padded_key)
    return base64.b64encode(encrypted_key)


braced_param = re.compile("{(\w+)}")


def get_user_directory(username):
    directory = os.path.join(USER_DIRECTORY, username)
    if not os.path.exists(directory):
        os.mkdir(directory)
    return directory

def get_user_log_directory(username):
    user_dir = get_user_directory(username)
    log_dir = os.path.join(user_dir, LOG_DIRECTORY_NAME)
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)
    return log_dir


def get_job_log(username, job_id, line_num=10):
    log_dir = get_user_log_directory(username)
    job_fp = os.path.join(log_dir, '{}'.format(job_id))
    if not os.path.exists(job_fp):
        return []

    if line_num > 100:
        line_num = 100
    with open(job_fp) as fp:
        return tail(fp, line_num)


def get_username(username):
    if username:
        return username
    job = get_current_job()
    return job.args[0]['username']


def get_logger(username=None):
    username = get_username(username)
    user_directory = get_user_directory(username)
    logger = logging.getLogger(username)
    logger.setLevel(logging.DEBUG)
    if not logger.handlers or not LOGGER_HANDLER_NAME in map(lambda l:l.name,
            logger.handlers):
        log_directory = get_user_log_directory(username)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler = logging.FileHandler(os.path.join(log_directory, job.id))
        handler.setFormatter(formatter)
        handler.name = LOGGER_HANDLER_NAME
        logger.addHandler(handler)
    return logger


def install_remote_logger(name):
    try:
        logger = get_logger()
    except Exception as e:
        return
    handler = logger.handlers[0]
    remote_logger = logging.getLogger(name)
    remote_logger.addHandler(handler)


def tail(f, window=20):
    """
    Taken from http://stackoverflow.com/questions/136168/get-last-n-lines-of-a-file-with-python-similar-to-tail
    Returns the last `window` lines of file `f` as a list.
    """
    if window == 0:
        return []
    BUFSIZ = 1024
    f.seek(0, 2)
    bytes = f.tell()
    size = window + 1
    block = -1
    data = []
    while size > 0 and bytes > 0:
        if bytes - BUFSIZ > 0:
            # Seek back one whole BUFSIZ
            f.seek(block * BUFSIZ, 2)
            # read BUFFER
            data.insert(0, f.read(BUFSIZ))
        else:
            # file too small, start from begining
            f.seek(0,0)
            # only read what was not read
            data.insert(0, f.read(bytes))
        linesFound = data[0].count('\n')
        size -= linesFound
        bytes -= BUFSIZ
        block -= 1
    return ''.join(data).splitlines()[-window:]

