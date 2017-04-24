import os
import pymongo
import re
import signal
import time
from bson.timestamp import Timestamp
from multiprocessing import Process

from crits.comments.comment import Comment
from crits.core.crits_mongoengine import create_embedded_source
from crits.core.handlers import add_releasability, add_releasability_instance, add_new_source
from crits.core.source_access import SourceAccess
from crits.core.user_tools import get_user_organization
from crits.ips.ip import IP
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.status import Status

from GeoIPLookup import geoip_lookup
from ASNLookup.ASNLookupData import ASNLookupData
from ASNLookup.ip_source_name_lookup import get_designated_source_name, get_primary_source_name

# global variables
process = None

def start_or_stop_service():
    global process
    if process is None:
        process = Process(target=process_from_oplog, args=())
        process.start()
        print "Started new process with PID: " + str(process.pid) + "."
    else:
        try:
            pid = process.pid
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        process.join()
        process = None

    # Wrap 'is_process_running()' with str() because otherwise it doesn't appear in UI when false.
    return {'success': True,
            'html': '',
            'process_status': process_status()}

def process_status():
    """
    Returns 'Running" if process is running, and 'Stopped' otherwise.
    :return: 'Running' or 'Stopped'
    """
    if (process is not None):
        return 'Running'
    return 'Stopped'

def process_from_oplog():
    client = pymongo.MongoClient()
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
                                cursor_type=pymongo.CursorType.TAILABLE_AWAIT,
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
            print(e.message)
            continue
    return

def rerun_service():
    try:
        for ip_object in IP.objects:
            analyze_ip_object(ip_object)
        return {'success': True,
                'html': ''}
    except Exception:
        return {'success': False,
                'html': ''}

def analyze_ip_object(ip_object):
    analyst = "analysis_autofill"
    asn_lookup_data = ASNLookupData(ip_object.ip, 'IPv4 Address')
    as_number = asn_lookup_data.as_number
    existing_source_name = get_name_of_source_with_as_number(as_number)
    if existing_source_name:
        designated_source_name = existing_source_name
    else:
        designated_source_name = get_designated_source_name(asn_lookup_data.as_name, asn_lookup_data.isp)
        primary_source_name = get_primary_source_name(designated_source_name)
        update_sources(as_number, asn_lookup_data.country_code, primary_source_name, designated_source_name)
    update_ip_object(ip_object, analyst, as_number, designated_source_name)

def get_name_of_source_with_as_number(as_number):
    """
    Return the name of a source, if any, that has the input AS Number.
    :param as_number: string
    :return: string, representing the name of the source with the input AS Number, or None if no such source exists
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

def update_sources(as_number, country_code, primary_source_name, designated_source_name):
    """
    Update primary and designated sources that will be added to whose name is AS Name of input data, or add this source if it does not yet exist.
    :return:
    """
    designated_source = get_source_object_from_name(designated_source_name)
    if not designated_source:
        # Create new source whose name is designated_source_name.
        add_new_source(designated_source_name, as_number, '')
        designated_source = get_source_object_from_name(designated_source_name)
    # Hopefully source exists by this point, but an error may have occurred when creating a new source.
    if designated_source:
        try:
            as_number_int = int(as_number)
            if as_number_int not in designated_source.asns:
                designated_source.asns.append(as_number_int)
        except (TypeError, ValueError):
            pass
        designated_source.country_code = country_code
        if designated_source_name != primary_source_name:
            primary_source = get_source_object_from_name(primary_source_name)
            if not primary_source:
                add_new_source(primary_source_name, '', '')
                primary_source = get_source_object_from_name(primary_source_name)
            # Hopefully source exists by this point, but an error may have occurred when creating a new source.
            if primary_source:
                merge_aliases(designated_source, primary_source)
                primary_source.save()
        designated_source.save()
    return

# TODO: will this handle the case where there is no such source (i.e. will it return None/Null?)?
def get_source_object_from_name(source_name):
    """
    Return source object whose name is source_name.
    :param source_name: string
    :return: source object, or None if no source has name source_name
    """
    sources = SourceAccess.objects(name=source_name).first()
    return sources

def merge_aliases(source_one, source_two):
    """
    Combine aliases of both input sources, including themselves, and set aliases of both sources to the combined list.
    :param source_one: 
    :param source_two: 
    :return: (nothing)
    """
    update_first_source_aliases_with_second_source_aliases(source_one, source_two)
    update_first_source_aliases_with_second_source_aliases(source_two, source_one)
    return

def update_first_source_aliases_with_second_source_aliases(first_source, second_source):
    """
    Add Second Source, and all aliases of Second Source, to aliases of First Source.
    :param first_source: 
    :param second_source: 
    :return: (nothing)
    """
    if second_source.name not in first_source.aliases:
        first_source.aliases.append(second_source.name)
    for alias in second_source.aliases:
        if alias != first_source.name and alias not in first_source.aliases:
            first_source.aliases.append(alias)
    return

##### Updating IP Object #####

def update_ip_object(ip_object, analyst, as_number, designated_source_name):
    """
    Update the given IP object, making sure that the IP's AS Number matches the input, and the designated source is a 
    source of the IP.
    :param ip_object: 
    :param analyst: The name of the user through which new objects will be added to the IP object.
    :param as_number: The AS Number that our ASN Service found.
    :type as_number: string
    :param designated_source_name: 
    :return: 
    """
    amend_as_number(ip_object, analyst, as_number)
    update_ip_object_sub_object(ip_object, analyst, ObjectTypes.AS_NAME, designated_source_name)
    add_source_to_ip(ip_object, analyst, designated_source_name)
    amend_geoip_data(ip_object, analyst)
    ip_object.set_status(Status.ANALYZED)
    # TODO: Potential looping problem because saving data to IP will add another entry to the audit_log.
    ip_object.save(username=analyst)
    return

def amend_as_number(ip_object, analyst, as_number):
    current_as_number = get_as_number_from_ip_object(ip_object)
    if current_as_number != as_number:
        if as_number:
            update_ip_object_sub_object(ip_object, analyst, ObjectTypes.AS_NUMBER, as_number)
            incorrect_asn_comment = "Error: Incorrect ASN given to IP. Corrected by analysis."
            add_comment_to_ip_object(ip_object, analyst, incorrect_asn_comment)
        else:
            null_asn_comment = "Warning: No AS Number found in database, but user gave value '" + current_as_number + "'."
            add_comment_to_ip_object(ip_object, analyst, null_asn_comment)

def get_as_number_from_ip_object(ip_object):
    """
    :param ip_object:
    :return: string
    """
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.AS_NUMBER:
            return o.value
    return ''

def update_ip_object_sub_object(ip_object, analyst, sub_object_type, sub_object_value):
    """
    For the given IP object, set the value of the sub-object of the given type to the input value.
    Before this, remove all other sub-objects of the given type.
    :param ip_object: 
    :param analyst: The name of the user through which new objects will be added to the IP object.
    :param sub_object_type:
    :param sub_object_value:
    :return: 
    """
    if not (sub_object_type and sub_object_value):
        return
    # To prevent skipping objects while iterating through IP's sub-objects, store list of objects to remove later.
    previous_object_values = []
    for o in ip_object.obj:
        if o.object_type == sub_object_type:
            previous_object_values.append(o.value)
    for prev_value in previous_object_values:
        ip_object.remove_object(sub_object_type, prev_value)
    ip_object.add_object(sub_object_type, sub_object_value, get_user_organization(analyst), '', '', analyst)
    return

def add_comment_to_ip_object(ip_object, analyst, content):
    """
    Add a new comment indicating the ASN was wrong.
    Based on comment_add() in crits/crits/comments/handlers.py.
    :param ip_object: The top-level IP object to add the comment to.
    :type ip_object: IP
    :param analyst: The name of the user adding the comment.
    :type analyst: str
    :param content: The content to use for the content object of the IP object.
    :type content: str
    :returns: (nothing)
    """
    comment = Comment()
    comment.comment = content
    comment.parse_comment()
    comment.set_parent_object('IP', ip_object.id)
    comment.analyst = analyst
    source = create_embedded_source(name=get_user_organization(analyst),
                                    analyst=analyst)
    comment.source = [source]
    comment.save(username=analyst)
    return

def add_source_to_ip(ip_object, analyst, source_name):
    """
    Adds a new source to the IP object's list of sources, if it is not already there.
    Assumes that source exists in source database.
    :param ip_object:
    :param analyst: The name of the user adding the source.
    :param source_name:
    :return:
    """
    if not source_name:
        return
    for src in ip_object.source:
        if src.name == source_name:
            # Source already in IP's sources
            return
    source = create_embedded_source(source_name, analyst=analyst)
    if source:
        ip_object.add_source(source)
        # Add a brand new releasability, and add an instance to that releasability.
        add_releasability('IP', ip_object.id, source.name, analyst)
        add_releasability_instance('IP', ip_object.id, source.name, analyst)
    return

##### GeoIP Lookup #####

def amend_geoip_data(ip_object, analyst):
    lookup_result = geoip_lookup.get_coordinates(ip_object.ip)
    if lookup_result:
        lookup_latitude, lookup_longitude = lookup_result
        input_result = get_coordinates_from_ip_object(ip_object)
        if input_result:
            input_latitude, input_longitude = input_result
            is_near_enough = (near_enough(input_latitude, lookup_latitude) and near_enough(input_longitude, lookup_longitude))
            if is_near_enough:
                # values in collection match lookup, so we don't need to change anything
                return
            ip_object.remove_object(ObjectTypes.LATITUDE, str(input_latitude))
            ip_object.remove_object(ObjectTypes.LONGITUDE, str(input_longitude))
        # TODO: I forget why I still add an error comment when input_result is null.
        coordinates_string = str(lookup_latitude) + "," + str(lookup_longitude)
        incorrect_coordinates_comment = "Error: Incorrect GeoIP coordinates. Correct coordinates: " + coordinates_string + "."
        add_comment_to_ip_object(ip_object, analyst, incorrect_coordinates_comment)
        ip_object.add_object(ObjectTypes.LATITUDE, str(lookup_latitude), get_user_organization(analyst), '', '', analyst)
        ip_object.add_object(ObjectTypes.LONGITUDE, str(lookup_longitude), get_user_organization(analyst), '', '', analyst)
    return

def get_coordinates_from_ip_object(ip_object):
    """
    Get coordinates saved to the IP object in the IP collection.
    :param ip_object: 
    :return: 
    """
    latitude = None
    longitude = None
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.LATITUDE:
            try:
                latitude = float(o.value)
            except (TypeError, ValueError):
                return None
        if o.object_type == ObjectTypes.LONGITUDE:
            try:
                longitude = float(o.value)
            except (TypeError, ValueError):
                return None
        if (latitude is not None) and (longitude is not None):
            return (latitude, longitude)
    return None

def near_enough(x, y):
    max_diff = 0.0001
    return abs(x - y) < max_diff