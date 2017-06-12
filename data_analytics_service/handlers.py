import os
from pymongo import MongoClient, CursorType
import signal
import time
from bson.timestamp import Timestamp
from multiprocessing import Process

from crits.ips.ip import IP
from crits.vocabulary.status import Status

from update_database import analyze_and_update_ip_object

# Global variables
process = None


def process_status():
    global process
    if process is None:
        return 'Stopped'
    return 'Running'


def start_or_stop_service():
    global process
    is_success = True
    status = 'Stopped'
    try:
        if process is None:
            process = Process(target=process_from_oplog, args=())
            process.start()
            print "Started new process with PID: " + str(process.pid) + "."
            status = 'Running'
        else:
            pid = process.pid
            os.kill(pid, signal.SIGKILL)
            process.join()
            process = None
    except Exception:
        is_success = False
    return {'success': is_success,
            'html': '',
            'process_status': status}


def process_from_oplog():
    client = MongoClient()
    oplog = client.local.oplog.rs
    #first_entry = oplog.find().sort('ts', pymongo.ASCENDING).limit(1).next()
    #timestamp = first_entry['ts']
    timestamp = Timestamp(1496182552, 1)
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
                for doc in cursor:
                    timestamp = doc['ts']
                    object_id = doc['o']['target_id']
                    ip_object = IP.objects(id=object_id).first()
                    if ip_object and ip_object.status == Status.IN_PROGRESS:
                        analyze_and_update_ip_object(ip_object)
                time.sleep(1)
        except Exception as e:
            print("Error while processing oplog: " + e.message)
            continue
    return


def rerun_service():
    """
    Re-analyze all IP objects in the database.
    :return: (nothing)
    """
    try:
        for ip_object in IP.objects:
            if ip_object.status != Status.NEW:
                analyze_and_update_ip_object(ip_object)
        return {'success': True,
                'html': ''}
    except Exception as e:
        print("Error while re-run processing: " + e.message)
        return {'success': False,
                'html': ''}
