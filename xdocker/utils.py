import os

from config import USER_DIRECTORY


def decrypt_key(key):
    return key


def encrypt_key(key):
    return key


def get_user_directory(username):
    directory =  os.path.join(USER_DIRECTORY, username)
    if not os.path.exists(directory):
        os.mkdir(directory)
    return directory

