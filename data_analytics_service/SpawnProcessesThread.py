from datetime import datetime
from threading import Thread
import time
from pymongo import MongoClient, CursorType
from bson.timestamp import Timestamp
import Queue
from multiprocessing import Process

from crits.ips.ip import IP
from crits.vocabulary.status import Status

from update_database import analyze_and_update_ip_object


class SpawnProcessesThread(Thread):
    def __init__(self, shutdown_queue, analyzer_processes_queue, bounded_semaphore):
        Thread.__init__(self)
        self.shutdown_queue = shutdown_queue
        self.analyzer_processes_queue = analyzer_processes_queue
        self.bounded_semaphore = bounded_semaphore

    def run(self):
        client = MongoClient(connect=False)
        oplog = client.local.oplog.rs
        # first_entry = oplog.find().sort('ts', pymongo.ASCENDING).limit(1).next()
        # timestamp = first_entry['ts']
        timestamp = Timestamp(1502928000, 1)
        #processes_array = []
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
                    start_time = datetime.now()
                    number_of_documents = 0
                    for doc in cursor:
                        print "Start of iteration in cursor loop."
                        number_of_documents += 1
                        print "Incremented count."
                        timestamp = doc['ts']
                        print "Changed timestamp."
                        self.bounded_semaphore.acquire()
                        print "A process is available."
                        if not self.shutdown_queue.empty():
                            break
                        object_id = doc['o']['target_id']
                        print "Got object ID."
                        p = Process(target=analyze_document, args=(object_id,))
                        print "Made new process."
                        p.start()
                        self.analyzer_processes_queue.put(p)
                        print "Current document count:"+str(number_of_documents)
                    end_time = datetime.now()
                    duration = end_time - start_time
                    print "Time:" + str(duration)
                    print "Number of documents: " + str(number_of_documents)
                    if not self.shutdown_queue.empty():
                        break
                    time.sleep(1)
            except Exception as e:
                print("Error while processing oplog: " + e.message)
                continue
            if not self.shutdown_queue.empty():
                break


def analyze_document(object_id):
    # do analytics with document
    print "analyze_document(): Start"
    ip_object = IP.objects(id=object_id).first()
    print "analyze_document(): Got IP object"
    #if ip_object:
    #    print "IP:"+ip_object.ip
    #else:
    #    print "IP:(none), ID:"+object_id
    if ip_object and ip_object.status == Status.IN_PROGRESS:
        print "analyze_document(): Analyzing IP."
        analyze_and_update_ip_object(ip_object)
    print "analyze_document(): Done"
