from threading import Thread
import time
from pymongo import MongoClient, CursorType, ASCENDING
from multiprocessing import Process

from crits.ips.ip import IP
from crits.vocabulary.status import Status

from update_database import analyze_and_update_ip_object


class SpawnProcessesThread(Thread):
    def __init__(self, shutdown_queue, analyzer_processes_queue, bounded_semaphore, iteration_unit):
        Thread.__init__(self)
        self.shutdown_queue = shutdown_queue
        self.analyzer_processes_queue = analyzer_processes_queue
        self.bounded_semaphore = bounded_semaphore
        self.iteration_unit = iteration_unit

    def run(self):
        client = MongoClient(connect=False)
        oplog = client.local.oplog.rs
        first_entry = oplog.find().sort('ts', ASCENDING).limit(1).next()
        timestamp = first_entry['ts']
        while True:
            try:
                if self.iteration_unit == 'oplog':
                    queryset = {'ts': {'$gt': timestamp},
                                'ns': 'crits.audit_log',
                                'o.type': 'IP'}
                    # oplog is capped collection, so it can be tailed
                    cursor = oplog.find(queryset,
                                        cursor_type=CursorType.TAILABLE_AWAIT,
                                        oplog_replay=True)
                    cursor.add_option(8)
                    while cursor.alive:
                        for doc in cursor:
                            timestamp = doc['ts']
                            self.bounded_semaphore.acquire()
                            if not self.shutdown_queue.empty():
                                self.bounded_semaphore.release()
                                break
                            object_id = doc['o']['target_id']
                            p = Process(target=analyze_document, args=(object_id,))
                            p.start()
                            self.analyzer_processes_queue.put(p)
                        if not self.shutdown_queue.empty():
                            break
                elif self.iteration_unit == 'ips':
                    ips = client.crits.ips
                    ip_objects = ips.find({'status': 'In Progress'})
                    for ip_object in ip_objects:
                        self.bounded_semaphore.acquire()
                        if not self.shutdown_queue.empty():
                            self.bounded_semaphore.release()
                            break
                        p = Process(target=analyze_and_update_ip_object, args=(ip_object,))
                        p.start()
                        self.analyzer_processes_queue.put(p)
                    time.sleep(1)
            except Exception as e:
                print("Error while processing oplog: " + e.message)
                continue
            if not self.shutdown_queue.empty():
                break


# Do analytics with IP object whose ID is the input ID.
def analyze_document(object_id):
    ip_object = IP.objects(id=object_id).first()
    if ip_object and ip_object.status == Status.IN_PROGRESS:
        analyze_and_update_ip_object(ip_object)
