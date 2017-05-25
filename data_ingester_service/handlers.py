from datetime import datetime
import ipaddress

from crits.events.event import Event
from crits.events.handlers import add_new_event
from crits.ips.ip import IP
from crits.ips.handlers import ip_add_update
from crits.vocabulary.events import EventTypes
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.relationships import RelationshipTypes


def save_ingest_data(analyst, source, ingest_data_entries):
    """
    Adds or updates multiple IP objects in the database using the ingest data.

    :param analyst: The analyst who sent the POST message for the IP objects.
    :type analyst: str
    :param source: The source of the POST message for the IP objects.
    :type source: str
    :param ingest_data_entries: A list of objects with data about attacks from IP addresses.
    :type ingest_data_entries: list of dictionaries, each conforming to an 'ingestData' object in the definitions of the data ingester payload schema
    :return: (nothing)
    """
    for ingest_data_entry in ingest_data_entries:
        ip_address = ingest_data_entry.get('IPaddress')
        add_new_ip_object(analyst, source, ip_address)
        ip_object = IP.objects(ip=ip_address).first()
        if not ip_object:
            raise Exception('IP object not found in database, even though result indicated success.')
        update_ip_object_additional_fields(analyst, source, ip_object)
        ip_object_id = ip_object.id
        save_new_event(analyst, source, ip_address, ip_object_id, ingest_data_entry)


def add_new_ip_object(analyst, source, ip_address):
    """
    Adds a new IP object, whose IP is the input address, to the database if one doesn't already exist.
    
    :param analyst: The analyst who sent the POST message for the IP object.
    :type analyst: str
    :param source: The source of the POST message for the IP object.
    :type source: str
    :param ip_address: The IP address of the object to add or update.
    :type ip_address: str
    :return: (nothing) 
    """
    if not isinstance(ip_address, basestring):
        raise Exception("'ip_address' is not a string.")
    ip_type = ip_address_type(ip_address)
    # This will create a new object for the IP if one doesn't already exist.
    result = ip_add_update(ip_address=ip_address, ip_type=ip_type, source=source, analyst=analyst)
    if not result['success']:
        # TODO: Why can I use dot notation on result, even though it's a dictionary?
        raise Exception(result.message)
    return


def ip_address_type(ip):
    """
    Return a string representing the version of the input IP address, to be used when adding/updating IP object.

    :param ip: The IP address to analyze.
    :type ip: str
    :return: str, either 'IPv4 Address' or 'IPv6 Address'
    :raise ValueError: ip does not represent a valid IP address
    """
    try:
        ip_address = ipaddress.ip_address(ip)
        if type(ip_address) == ipaddress.IPv4Address:
            return 'IPv4 Address'
        else:
            return 'IPv6 Address'
    except ValueError:
        raise ValueError('IP is not a valid IPv4 or IPv6 address.')


def update_ip_object_additional_fields(analyst, source, ip_object):
    """
    Updates additional fields for the IP object.
    
    :param analyst: The analyst who sent the POST message for the IP object.
    :type analyst: str
    :param source: The source of the POST message for the IP object.
    :type source: str
    :param ip_object: The IP object to update.
    :type ip_object: IP
    :return: (nothing)
    """
    # This dictionary indicates whether each type of sub-object we want to change was already present in the IP object.
    is_sub_object_present = {
        ObjectTypes.TIME_LAST_SEEN: False,
        ObjectTypes.NUMBER_OF_TIMES_SEEN: False,
        ObjectTypes.NUMBER_OF_REPORTERS: False
        # For now, 'reportedBy' field will be calculated in distribution service.
    }
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.TIME_LAST_SEEN:
            current_time_string = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            o.value = current_time_string
            is_sub_object_present[ObjectTypes.TIME_LAST_SEEN] = True
        elif o.object_type == ObjectTypes.NUMBER_OF_TIMES_SEEN:
            # Increment number of times seen
            try:
                int_value = int(o.value)
                int_value += 1
                o.value = str(int_value)
            except (TypeError, ValueError):
                pass
            is_sub_object_present[ObjectTypes.NUMBER_OF_TIMES_SEEN] = True
        elif o.object_type == ObjectTypes.NUMBER_OF_REPORTERS:
            number_of_reporters = get_number_of_reporters(ip_object)
            o.value = str(number_of_reporters)
            is_sub_object_present[ObjectTypes.NUMBER_OF_REPORTERS] = True
    # Create new sub-objects for types that were not present.
    if not is_sub_object_present[ObjectTypes.TIME_LAST_SEEN]:
        current_time_string = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        ip_object.add_object(ObjectTypes.TIME_LAST_SEEN, current_time_string, source, '', '', analyst)
    if not is_sub_object_present[ObjectTypes.NUMBER_OF_TIMES_SEEN]:
        ip_object.add_object(ObjectTypes.NUMBER_OF_TIMES_SEEN, '1', source, '', '', analyst)
    if not is_sub_object_present[ObjectTypes.NUMBER_OF_REPORTERS]:
        number_of_reporters = get_number_of_reporters(ip_object)
        ip_object.add_object(ObjectTypes.NUMBER_OF_REPORTERS, str(number_of_reporters), source, '', '', analyst)
    ip_object.save(username=analyst)


def get_number_of_reporters(ip_object):
    """
    Return the number of reporters to the IP object, calculated as the number of sources the object has, excluding the
    source that owns the IP.
    
    :param ip_object: The IP object for which we want to find the number of reporters.
    :type ip_object: IP
    :return: int
    """
    source_aggregation_pipeline = [
        {'$match': {'ip': ip_object.ip}},
        {'$project': {'_id': 0, 'source': 1}},
        {'$unwind': '$source'},
        {'$group': {'_id': 1, 'sources': {'$push': '$source.name'}}},
        {'$project': {'_id': 0, 'sources': 1}}
    ]
    source_aggregation_result = IP.objects.aggregate(*source_aggregation_pipeline, useCursor=False)
    source_names = []
    for item in source_aggregation_result:
        source_names = item['sources']
        break
    releasability_aggregation_pipeline = [
        {'$match': {'ip': ip_object.ip}},
        {'$project': {'_id': 0, 'releasability': 1}},
        {'$unwind': '$source'},
        {'$group': {'_id': 1, 'names': {'$push': '$source.name'}}},
        {'$project': {'_id': 0, 'names': 1}}
    ]
    releasability_aggregation_result = IP.objects.aggregate(*releasability_aggregation_pipeline, useCursor=False)
    releasability_names = []
    for item in releasability_aggregation_result:
        releasability_names = item['names']
        break
    reporters_set = set(source_names).difference(set(releasability_names))
    return len(reporters_set)


def save_new_event(analyst, source, ip_address, ip_object_id, ingest_data_entry):
    """
    Save relevant information from ingest data into a new event associated with the IP address.
    
    :param analyst: The analyst who sent the POST message for the IP object.
    :type analyst: str
    :param source: The source of the POST message for the IP object.
    :type source: str
    :param ip_address: The IP address of the object to associate the event with.
    :type ip_address: str
    :param ip_object_id: The ID of the IP object associated with the IP address.
    :type ip_object_id: str
    :param ingest_data_entry: An object with data about attacks from the IP address.
    :type ingest_data_entry: dict, conforming to an 'ingestData' object in the definitions of the data ingester payload schema
    :return: (nothing)
    """
    current_time = datetime.now()
    title = "IP:[" + ip_address + "],Time:[" + current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ') + "]"
    result = add_new_event(title=title,
                           description='',
                           event_type=EventTypes.DISTRIBUTED_DENIAL_OF_SERVICE,
                           source=source,
                           method='',
                           reference='',
                           date=current_time,
                           analyst=analyst,
                           related_id=ip_object_id,
                           related_type='IP',
                           relationship_type=RelationshipTypes.RELATED_TO
                           )
    if not result['success']:
        raise Exception('Failed to add event for IP object: ' + result.message)
    event_object = Event.objects(id=result['id']).first()

    object_types_to_field_names = {
        ObjectTypes.ATTACK_START_TIME: 'attackStartTime',
        ObjectTypes.ATTACK_STOP_TIME: 'attackStopTime',
        # time recorded will simply be the "created" time, which should be set to 'current_time' from this function
        # handle attack types differently
        ObjectTypes.TOTAL_BYTES_SENT: 'totalBytesSent',
        ObjectTypes.TOTAL_PACKETS_SENT: 'totalPacketsSent',
        ObjectTypes.PEAK_BYTES_PER_SECOND: 'peakBPS',
        ObjectTypes.PEAK_PACKETS_PER_SECOND: 'peakPPS',
        ObjectTypes.SOURCE_PORT: 'sourcePort',
        ObjectTypes.DEST_PORT: 'destinationPort',
        ObjectTypes.PROTOCOL: 'protocol'
    }
    for object_type, field_name in object_types_to_field_names.items():
        field_value = ingest_data_entry.get(field_name)
        if field_value:
            event_object.add_object(object_type=object_type,
                                    value=str(field_value),
                                    source=source,
                                    method='',
                                    reference='',
                                    analyst=analyst
                                    )
    # Handle Attack Types differently because this is an array field. Add an Attack Type object for each value.
    attack_types = ingest_data_entry.get('attackTypes')
    if attack_types:
        for atk_type in attack_types:
            event_object.add_object(object_type=ObjectTypes.ATTACK_TYPE,
                                    value=atk_type,
                                    source=source,
                                    method='',
                                    reference='',
                                    analyst=analyst
                                    )
    event_object.save(username=analyst)
