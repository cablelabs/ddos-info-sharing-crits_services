from multiprocessing import Process
import os, signal, time

import pymongo
from pymongo import cursor

process = None

def start_service():
    global process
    if process is None:
        process = Process(target=process_data, args=())
        process.start()
    else:
        try:
            os.kill(process.pid, signal.SIGKILL)
        except OSError:
            pass
        process.join()
        process = None

    is_processing_data = (process is not None)

    # Wrap 'is_processing_data' with str() because otherwise it doesn't appear in UI when false.
    return {'success': True,
            'html': '',
            'is_processing_data': str(is_processing_data)}

def process_data():
    client = pymongo.MongoClient()
    #oplog = client.local.oplog.rs
    #TODO: ASCENDING or DESCENDING?
    audit_log = client.crits.audit_log
    first_entry = audit_log.find().sort('date', pymongo.ASCENDING).limit(1).next()
    date = first_entry['date']

    while True:
        cursor = audit_log.find({'date': {'$gt': date}},
                                tailable=True,
                                await_data=True)
        #cursor.add_option(8)
        while cursor.alive:
            for doc in cursor:
            #for i in range(count):
                #doc = cursor[i]
                date = doc['date']
                #TODO: Do something...
            time.sleep(1)