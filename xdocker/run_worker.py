from rq import Connection, Queue, Worker


def worker_exc_handler(job, exc_type, exc_value, traceback):
    job.meta['exc_code'] = exc_type.code
    job.meta['exc_message'] = exc_type.message
    return True


def main():
    with Connection():
        q = Queue()
        worker = Worker([q])
        worker.push_exc_handler(worker_exc_handler)
        worker.work()

if __name__ == '__main__':
    main()