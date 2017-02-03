from multiprocessing import Process
import commands
import os, signal, time, re
from bson.timestamp import Timestamp

import pymongo, pygeoip, requests
from crits.ips.ip import IP
from crits.comments.comment import Comment
from crits.comments.views import add_update_comment
from crits.core.crits_mongoengine import create_embedded_source
from crits.core.handlers import add_releasability, add_releasability_instance, add_new_source
from crits.core.source_access import SourceAccess
from crits.core.user_tools import get_user_organization
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.status import Status

from DnsLookupData import DnsLookupData

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
    timestamp = Timestamp(1482178094, 1) #first_entry['ts']
    while True:
        try:
            queryset = {'ts': {'$gt': timestamp},
                        'ns': 'crits.audit_log',
                        'o.type': 'IP'}
            # oplog is capped collection, so it can be tailed
            cursor = oplog.find(queryset,
                                tailable=True,
                                await_data=True)
            cursor.add_option(8)
            while cursor.alive:
                for doc in cursor:
                    timestamp = doc['ts']
                    object_id = doc['o']['target_id']
                    ip_object = IP.objects(id=object_id).first()
                    if (ip_object and ip_object.status != Status.ANALYZED):
                        analyze_ip_entry(ip_object)
                time.sleep(1)
        except Exception as e:
            print(e.message)
            continue
    return

def rerun_service():
    try:
        client = pymongo.MongoClient()
        ips = client.crits.ips
        all_ip_entries = ips.find()
        for ip_entry in all_ip_entries:
            ip_object = IP.objects(id=ip_entry['_id']).first()
            analyze_ip_entry(ip_object)
        return {'success': True,
                'html': ''}
    except Exception:
        return {'success': False,
                'html': ''}

def analyze_ip_entry(ip_object):
    if ip_object:
        username = "analysis_autofill"
        dns_lookup_data = DnsLookupData(ip_object.ip, 'IPv4 Address')
        new_source_name = update_sources(dns_lookup_data)
        update_ip_object(ip_object, username, new_source_name, dns_lookup_data.as_number)
        check_GeoIP_data(ip_object, username)


##### Updating Sources #####

def update_sources(dns_lookup_data):
    """
    Update source whose name is AS Name, possibly creating a new source. Then add this source to Alias list of
    over-arching source, and vice-versa.
    :param dns_lookup_data: A DnsLookupData object.
    :return: Name of source, as a string, that should be added to the IP object being analyzed.
    """
    as_name = dns_lookup_data.as_name

    unresolved_names_pattern = "^.$|^(?!.*[A-Za-z])|Private$|Reserved$|^ASN|^AS(?![A-Za-z])"
    is_as_name_unresolved_result = re.search(unresolved_names_pattern, as_name)
    if is_as_name_unresolved_result:
        isp_name = dns_lookup_data.isp
        is_isp_unresolved_result = re.search(unresolved_names_pattern, isp_name)
        source_name = isp_name
        if is_isp_unresolved_result:
            source_name = as_name
        unresolved_source = find_source_from_name("TBD-UNRESOLVED")
        if unresolved_source:
            if as_name not in unresolved_source.aliases:
                unresolved_source.aliases.append(source_name)
                unresolved_source.save()
        add_update_as_name_source(dns_lookup_data, "TBD-UNRESOLVED")
        return source_name

    region_specific_names_pattern = "^([A-Za-z]*)-(.*)"
    region_specific_names_result = re.search(region_specific_names_pattern, as_name)
    if region_specific_names_result:
        prefix_sub_string = region_specific_names_result.group(1)
        source = find_source_from_name(prefix_sub_string)
        if not source:
            # No existing source with name of sub-string, so create one
            add_new_source(prefix_sub_string, '', '')
            source = find_source_from_name(prefix_sub_string)
        # Hopefully source exists by this point, but an error may have occurred when creating a new source.
        if source:
            if as_name not in source.aliases:
                source.aliases.append(as_name)
                source.save()
        add_update_as_name_source(dns_lookup_data, prefix_sub_string)
        return as_name

    add_update_as_name_source(dns_lookup_data, '')
    return as_name

def add_update_as_name_source(dns_lookup_data, additional_alias):
    """
    Update source whose name is AS Name of input data, or add this source if it does not yet exist.
    :param dns_lookup_data: DNS Lookup data.
    :param additional_alias: String representing which source to add to aliases field.
    :return:
    """
    as_number = dns_lookup_data.as_number
    as_name = dns_lookup_data.as_name
    # TODO: See how my regex handles emtpy name. What ASN would give an empty name?
    if as_name:
        as_name_source = find_source_from_name(as_name)
        if not as_name_source:
            # No existing source with AS Name, so create one
            add_new_source(as_name, as_number, '')
            as_name_source = find_source_from_name(as_name)
        # Hopefully source exists by this point, but an error may have occurred when creating a new source.
        if as_name_source:
            try:
                as_number_int = int(as_number)
                if as_number_int not in as_name_source.asns:
                    as_name_source.asns.append(as_number_int)
            except (TypeError, ValueError):
                pass
            as_name_source.country_code = dns_lookup_data.country_code
            if additional_alias:
                as_name_source.aliases.append(additional_alias)
            as_name_source.save()
    return

# Iterate through sources to see if source with input name exists.
def find_source_from_name(source_name):
    sources = SourceAccess.objects()
    for src in sources:
        if source_name == src.name:
            return src
    return None


##### Updating IP Object #####

def update_ip_object(ip_object, username, new_source_name, as_number):
    current_as_number = get_asn_str_from_object(ip_object)
    if current_as_number != as_number:
        update_ip_object_asn(ip_object, username, as_number)
        add_flag_comment_to_ip(ip_object, username)
    update_ip_object_as_name(ip_object, new_source_name, username)
    add_source_to_ip(ip_object, username, new_source_name)
    ip_object.set_status(Status.ANALYZED)
    # TODO: potential looping problem because this will add another entry to the audit_log
    ip_object.save(username=username)
    return

def get_asn_str_from_object(ip_object):
    """
    :param ip_object:
    :return: string
    """
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.AS_NUMBER:
            return o.value
    return ''

def update_ip_object_asn(ip_object, username, as_number):
    if not as_number:
        return
    # First, remove old AS Number object(s)
    # To prevent skipping objects in ip_object.obj due to removing objects, store list of ASNs to remove.
    asn_values = []
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.AS_NUMBER:
            asn_values.append(o.value)
    for asn_value in asn_values:
        ip_object.remove_object(ObjectTypes.AS_NUMBER, asn_value)

    # Add new AS Number object
    ip_object.add_object(ObjectTypes.AS_NUMBER, as_number, 'analysis_autofill', '', '', username)
    return

def add_flag_comment_to_ip(ip_object, analyst):
    """
    Add a new comment indicating the ASN was wrong.
    Based on comment_add() in crits/crits/comments/handlers.py.
    :param ip_object: The top-level IP object to add the comment to.
    :type ip_object: IP
    :param analyst: The user adding the comment.
    :type analyst: str
    :returns: (nothing)
    """
    comment = Comment()
    comment.comment = "Error: Incorrect ASN given to IP. Corrected by analysis."
    comment.parse_comment()
    comment.set_parent_object('IP', ip_object.id)
    comment.analyst = analyst
    source = create_embedded_source(name=get_user_organization(analyst),
                                    analyst=analyst)
    comment.source = [source]
    comment.save(username=analyst)
    #comment.reload()
    #comment.comment_to_html()
    return

def update_ip_object_as_name(ip_object, as_name, username):
    if not as_name:
        return
    # First, remove old AS Name object(s).
    # To prevent skipping objects in ip_object.obj due to removing objects, store list of AS Names to remove.
    old_as_names = []
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.AS_NAME:
            old_as_names.append(o.value)
    for old_as_name in old_as_names:
        ip_object.remove_object(ObjectTypes.AS_NAME, old_as_name)

    # add new AS Name object
    ip_object.add_object(ObjectTypes.AS_NAME, as_name, 'analysis_autofill', '', '', username)
    return

def add_source_to_ip(ip_object, username, source_name):
    """
    Adds a new source to the IP object's list of sources, if it is not already there.
    Assumes that source exists in source database.
    :param ip_object:
    :param username:
    :return:
    """
    if not source_name:
        return
    is_source_in_ip_sources = False
    for src in ip_object.source:
        if src.name == source_name:
            is_source_in_ip_sources = True
            break
    if not is_source_in_ip_sources:
        source = create_embedded_source(source_name, analyst=username)
        if source:
            ip_object.add_source(source)
            # Add a brand new releasability, and add an instance to that releasability.
            add_releasability('IP', ip_object.id, source.name, username)
            add_releasability_instance('IP', ip_object.id, source.name, username)


##### GeoIP Lookup #####

def check_GeoIP_data(ip_object, username):
    # NOTE: Use username if I want to modify objects in ip_object.
    input_latitude = 0
    input_longitude = 0
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.EXTRA:
            extra = o.value
            numbers = extra.split(",", 2)
            if len(numbers) < 2:
                return
            try:
                input_latitude = float(numbers[0])
                input_longitude = float(numbers[1])
            except (TypeError, ValueError):
                return
            break

    #gi = pygeoip.GeoIP('/usr/share/GeoIP/GeoIP.dat')
    #record = gi.record_by_addr(ip_object.ip)
    url = 'http://freegeoip.net/json/'+ip_object.ip
    r = requests.get(url)
    js = r.json()
    lookup_latitude = js['latitude']
    lookup_longitude = js['longitude']
    is_near_enough = (near_enough(input_latitude, lookup_latitude) and near_enough(input_longitude, lookup_longitude))
    if not is_near_enough:
        coordinates_string = str(lookup_latitude) + "," + str(lookup_longitude)
        add_geoip_comment_to_ip(ip_object, username, coordinates_string)
    return

def near_enough(x, y):
    max_diff = 0.0001
    return abs(x - y) < max_diff

def add_geoip_comment_to_ip(ip_object, analyst, coordinates_string):
    """
    Add a new comment indicating the latitude and longitude was wrong.
    Based on comment_add() in crits/crits/comments/handlers.py.
    :param ip_object: The top-level IP object to add the comment to.
    :type ip_object: IP
    :param analyst: The user adding the comment.
    :type analyst: str
    :returns: (nothing)
    """
    comment = Comment()
    comment.comment = "Error: Incorrect GeoIP coordinates. Correct coordinates: " + coordinates_string + "."
    comment.parse_comment()
    comment.set_parent_object('IP', ip_object.id)
    comment.analyst = analyst
    source = create_embedded_source(name=get_user_organization(analyst),
                                    analyst=analyst)
    comment.source = [source]
    comment.save(username=analyst)
    return