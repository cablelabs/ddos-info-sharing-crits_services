from datetime import datetime
import os
import Queue
from pymongo import MongoClient, CursorType
import signal
from bson.timestamp import Timestamp
from multiprocessing import Process, Pool
import socket

from crits.ips.ip import IP
from crits.vocabulary.status import Status

from AnalyzerThread import AnalyzerThread
from update_database import analyze_and_update_ip_object


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
                    #os.kill(config_pid, signal.SIGKILL)
                    # TODO: do NOT send kill, instead send message to socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect(('127.0.0.1', 9999))
                    #s.send("hey")
                    s.close()
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


def process_from_oplog():
    #is_processing = True
    is_processing_queue = Queue.Queue(1)
    analyzer_thread = AnalyzerThread(is_processing_queue)
    analyzer_thread.start()
    # listen for signal from button press
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 9999))
    server_socket.listen(5)
    conn, addr = server_socket.accept()
    server_socket.close()
    # if we get here, button has been pressed
    # tell analyzer_thread to stop processing
    is_processing_queue.put(True)
    analyzer_thread.join()
    print "doneeee"


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
