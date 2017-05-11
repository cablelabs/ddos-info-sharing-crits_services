import os
from pymongo import MongoClient, CursorType
import signal
import time
from bson.timestamp import Timestamp
from multiprocessing import Process

from crits.core.source_access import SourceAccess
from crits.ips.ip import IP
from crits.vocabulary.status import Status

from update_database import update_ip_object
from ASNLookup.ASNLookupData import ASNLookupData

# Global variables
process = None


def process_status():
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
    timestamp = Timestamp(1491238150, 1)
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
                    if (ip_object and ip_object.status != Status.ANALYZED):
                        analyze_ip_object(ip_object)
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
            analyze_ip_object(ip_object)
        return {'success': True,
                'html': ''}
    except Exception:
        return {'success': False,
                'html': ''}


def analyze_ip_object(ip_object):
    """
    Perform various analysis steps on the input IP object
    
    :param ip_object: The IP object to analyze.
    :type ip_object: IP
    :return: (nothing)
    """
    asn_lookup_data = ASNLookupData(ip_object.ip)
    as_number = asn_lookup_data.as_number
    as_name = asn_lookup_data.as_name
    source_name = get_name_of_source_with_as_number(as_number)
    update_ip_object(ip_object, as_number, as_name, source_name)


def get_name_of_source_with_as_number(as_number):
    """
    Return the name of a source, if any, that has the input AS Number.
    
    :param as_number: The number such that the source whose name we return contains this number.
    :type as_number: str
    :return: A string representing the name of a source, or None if no valid source exists
    """
    if as_number:
        try:
            as_number_int = int(as_number)
        except (TypeError, ValueError):
            return None
        source = SourceAccess.objects(asns=as_number_int).first()
        if source:
            return source.name
    return None