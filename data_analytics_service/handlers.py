from datetime import datetime
import os
from pymongo import MongoClient, CursorType
import signal
import time
from bson.timestamp import Timestamp
from multiprocessing import Process, Pool, Value

from crits.ips.ip import IP
from crits.vocabulary.status import Status

from update_database import analyze_and_update_ip_object

# Global variables
#pool = None


def process_status():
    client = MongoClient()
    service_config = client.crits.service_config
    config = service_config.find_one({})
    # Assume service is running only if configuration exists, and PID is set to a valid value.
    if config:
        pid = config['pid']
        if pid is not None:
            try:
                os.kill(pid, 0)
                return 'Running'
            except OSError:
                service_config.update_one({'_id': config['_id']}, {'$set': {'pid': None}})
    return 'Stopped'


def start_or_stop_service():
    is_success = True
    status = 'Running'
    try:
        client = MongoClient()
        service_config = client.crits.service_config
        config = service_config.find_one({})
        if config:
            config_pid = config['pid']
            if config_pid is None:
                process = Process(target=process_from_oplog, args=())
                process.start()
                service_config.update_one({'_id': config['_id']}, {'$set': {'pid': process.pid}})
            else:
                try:
                    os.kill(config_pid, signal.SIGKILL)
                    service_config.update_one({'_id': config['_id']}, {'$set': {'pid': None}})
                    status = 'Stopped'
                except OSError:
                    # Process already killed
                    process = Process(target=process_from_oplog, args=())
                    process.start()
                    service_config.update_one({'_id': config['_id']}, {'$set': {'pid': process.pid}})
        else:
            # Assume service is not running when configuration does not yet exist.
            # Even if it was running, we wouldn't know its PID.
            process = Process(target=process_from_oplog, args=())
            process.start()
            config = {'pid': process.pid}
            service_config.insert_one(config)
    except Exception as e:
        is_success = False
    return {'success': is_success,
            'html': '',
            'process_status': status}


def start_main_process():
    """
    Starts the main process that runs a continuous loop to monitor the oplog.
    :return: The PID of the newly-started process.
    """
    process = Process(target=process_from_oplog, args=())
    process.start()
    return process.pid


def process_from_oplog():
    #def cleanup(signum, frame):
    #    if pool is not None:
    #        pool.terminate()
    #signal.signal(signal.SIGINT, cleanup)
    client = MongoClient()
    oplog = client.local.oplog.rs
    #first_entry = oplog.find().sort('ts', pymongo.ASCENDING).limit(1).next()
    #timestamp = first_entry['ts']
    timestamp = Timestamp(1497600000, 1)
    number_of_processes = 10
    try:
        pool = Pool(processes=number_of_processes)
        while True:
            try:
                if pool is None:
                    pool = Pool(processes=number_of_processes)
                queryset = {'ts': {'$gt': timestamp},
                            'ns': 'crits.audit_log',
                            'o.type': 'IP'}
                # oplog is capped collection, so it can be tailed
                cursor = oplog.find(queryset,
                                    cursor_type=CursorType.TAILABLE_AWAIT,
                                    oplog_replay=True)
                cursor.add_option(8)
                while cursor.alive:
                    documents = []
                    for doc in cursor:
                        timestamp = doc['ts']
                        documents.append(doc)
                        # process_document(doc)
                    pool.imap_unordered(process_document, documents)
                    time.sleep(1)
            except Exception as e:
                print("Error while processing oplog: " + e.message)
                if pool is not None:
                    pool.terminate()
                    pool = None
                continue
    finally:
        if pool is not None:
            pool.terminate()


def process_document(doc):
    object_id = doc['o']['target_id']
    ip_object = IP.objects(id=object_id).first()
    # if ip_object:
    #     print "Viewing oplog entry for IP '" + ip_object.ip + "':"
    #     print doc
    if ip_object and ip_object.status == Status.IN_PROGRESS:
        analyze_and_update_ip_object(ip_object)


def rerun_service():
    """
    Re-analyze all IP objects in the database.
    :return: (nothing)
    """
    try:
        pool = Pool(processes=10)
        cursor = IP.objects
        ip_objects = list(cursor)#[ip for ip in cursor]
        start_time = datetime.now()
        #print "Start time:" + start_time.strftime("%H:%M:%SZ")
        pool.map(process_ip, ip_objects)
        # Version without multiple processes.
        # for ip_object in IP.objects:
        #     process_ip(ip_object)
        end_time = datetime.now() - start_time
        pool.terminate()
        print "Analysis time:" + str(end_time)
        return {'success': True,
                'html': ''}
    except Exception as e:
        print("Error while re-run processing: " + e.message)
        return {'success': False,
                'html': ''}


def process_ip(ip_object):
    #print "Checking status of IP " + ip_object.ip
    if ip_object.status != Status.NEW:
        #print "Processing IP " + ip_object.ip
        analyze_and_update_ip_object(ip_object)
