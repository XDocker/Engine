#!/usr/bin/env python
# encoding: utf-8

import os
import datetime

from config import USER_DIRECTORY, LOG_DIRECTORY_NAME, STORE_LOGS


NOW = datetime.datetime.now()

def clean_log(filepath):
    delete = False
    with open(filepath) as fp:
        line = fp.readline()
        try:
            date_str = ' '.join(line.split()[:1])
            log_start = datetime.datetime.strptime(date_str,
                    '%Y-%m-%d %H:%M:%S,%f')
        except StandardError:
            delete = True
        else:
            log_age = NOW - log_start
            if log_age.hours >= STORE_LOGS:
                delete = True
    if delete:
        print "Deleting {}".format(filepath)
        os.remove(filepath)


def main():
    for username in os.listdir(USER_DIRECTORY):
        log_dir = os.path.join(USER_DIRECTORY, username, LOG_DIRECTORY_NAME)
        if not os.path.exists(log_dir):
            continue
        for log in os.listdir(log_dir):
            clean_log(os.path.join(log_dir, log))


if __name__ == '__main__':
    main()
