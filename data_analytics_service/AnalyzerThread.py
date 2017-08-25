from threading import Thread
import time
from pymongo import MongoClient, CursorType
from bson.timestamp import Timestamp
import Queue
from multiprocessing import Process

from crits.ips.ip import IP
from crits.vocabulary.status import Status

from update_database import analyze_and_update_ip_object


class AnalyzerThread(Thread):
    def __init__(self, is_processing_queue):
        Thread.__init__(self)
        self.is_processing_queue = is_processing_queue

    def run(self):
        client = MongoClient()
        oplog = client.local.oplog.rs
        # first_entry = oplog.find().sort('ts', pymongo.ASCENDING).limit(1).next()
        # timestamp = first_entry['ts']
        timestamp = Timestamp(1498867200, 1)
        number_of_processes = 10
        # TODO: use array instead of queue, because the front process may complete after other processes, in which case
        # we should replace those other processes when the array gets full and we still have documents to analyze
        processes_queue = Queue.Queue(number_of_processes)
        while True:
            try:
                queryset = {'ts': {'$gt': timestamp},
                            'ns': 'crits.audit_log',
                            'o.type': 'IP'}
                # oplog is capped collection, so it can be tailed
                cursor = oplog.find(queryset,
                                    cursor_type=CursorType.TAILABLE_AWAIT,
                                    oplog_replay=True)
                cursor.add_option(8)
                while cursor.alive:
                    # iterate over all documents
                    for doc in cursor:
                        if not self.is_processing_queue.empty():
                            break
                        timestamp = doc['ts']
                        if processes_queue.full():
                            front_process = processes_queue.get()
                            front_process.join()
                        p = Process(target=analyze_document, args=(doc,))
                        p.start()
                        processes_queue.put(p)
                    if not self.is_processing_queue.empty():
                        while not processes_queue.empty():
                            front_process = processes_queue.get()
                            front_process.terminate()
                        break
                    time.sleep(1)
            except Exception as e:
                print("Error while processing oplog: " + e.message)
                continue
            if not self.is_processing_queue.empty():
                break


def analyze_document(doc):
    # do analytics with document
    object_id = doc['o']['target_id']
    ip_object = IP.objects(id=object_id).first()
    if ip_object and ip_object.status == Status.IN_PROGRESS:
        analyze_and_update_ip_object(ip_object)