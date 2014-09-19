import os

from config import USER_DIRECTORY, LOG_DIRECTORY_NAME


def decrypt_key(key):
    return key


def encrypt_key(key):
    return key


def get_user_directory(username):
    directory =  os.path.join(USER_DIRECTORY, username)
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

