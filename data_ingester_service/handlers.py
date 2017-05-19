from datetime import datetime
import ipaddress

from crits.events.event import Event
from crits.events.handlers import add_new_event
from crits.ips.ip import IP
from crits.ips.handlers import ip_add_update
from crits.vocabulary.events import EventTypes
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.relationships import RelationshipTypes


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


def add_or_update_ip_object_group(analyst, source, ip_objects):
    """
    Adds or updates multiple IP objects to the database.

    :param analyst: The analyst who sent the POST message for the IP objects.
    :type analyst: str
    :param source: The source of the POST message for the IP objects.
    :type source: str
    :param ip_objects: A group of IP objects to add or update.
    :type ip_objects: list of dictionaries, each conforming to the data ingester payload schema
    :return: (nothing)
    """
    for ip_obj in ip_objects:
        add_or_update_ip_object(analyst, source, ip_obj)


def add_or_update_ip_object(analyst, source, ip_object):
    """
    Adds or updates a single IP object to the database.
    
    :param analyst: The analyst who sent the POST message for the IP object.
    :type analyst: str
    :param source: The source of the POST message for the IP object.
    :type source: str
    :param ip_object: An IP object to add or update.
    :type ip_object: dict, conforming to the data ingester payload schema
    :return: (nothing)
    """
    ip = ip_object.get('IPaddress')
    if not isinstance(ip, basestring):
        raise Exception("IPaddress not a string.")
    ip_type = ip_address_type(ip)
    result = ip_add_update(ip_address=ip,
                           ip_type=ip_type,
                           source=source,
                           analyst=analyst
                           )
    if not result['success']:
        # TODO: Why can I use dot notation on result, even though it's a dictionary?
        raise Exception('Failed to add/update IP object: ' + result.message)
    new_ip_object = IP.objects(ip=ip).first()
    if not new_ip_object:
        raise Exception('IP not found in database, even though result indicated success.')
    add_internal_fields_to_ip_object(analyst, source, new_ip_object)
    ip_object_id = new_ip_object.id
    events = ip_object.get('events', None)
    save_ip_object_events(analyst, source, ip, ip_object_id, events)
    return


def add_internal_fields_to_ip_object(analyst, source, ip_object):
    is_number_of_times_seen_present = False
    # is_time_first_seen_present = False
    # is_time_last_seen_present = False
    # time_now = ''
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.NUMBER_OF_TIMES_SEEN:
            # Increment number of times seen
            try:
                int_value = int(o.value)
                int_value += 1
                o.value = str(int_value)
            except (TypeError, ValueError):
                pass
            is_number_of_times_seen_present = True
            break
        # elif o.object_type == ObjectTypes.TIME_FIRST_SEEN:
        #     is_time_first_seen_present = True
        # elif o.object_type == ObjectTypes.TIME_LAST_SEEN:
        #     # Update last time seen to current time
        #     time_now = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        #     o.value = time_now
        #     is_time_last_seen_present = True

    # Initialize number of times seen, first time seen, and last time seen if they are not present.
    if not is_number_of_times_seen_present:
        ip_object.add_object(ObjectTypes.NUMBER_OF_TIMES_SEEN, '1', source, '', '', analyst)
    # if not time_now:
    #     time_now = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    # if not is_time_first_seen_present:
    #     ip_object.add_object(ObjectTypes.TIME_FIRST_SEEN, time_now, source, '', '', analyst)
    # if not is_time_last_seen_present:
    #     ip_object.add_object(ObjectTypes.TIME_LAST_SEEN, time_now, source, '', '', analyst)
    ip_object.save(username=analyst)


def save_ip_object_events(analyst, source, ip_address, ip_object_id, events):
    """
    Save all events from the input IP object to the Events database, and associate them with the IP object.
    
    :param ip_object: The IP object to update.
    :type ip_object: dict, conforming to the data ingester payload schema
    :return: (nothing)
    """
    object_types_to_field_names = {
        ObjectTypes.TIMESTAMP: 'timestamp',
        ObjectTypes.TOTAL_BYTES_SENT: 'totalBytesSent',
        ObjectTypes.TOTAL_PACKETS_SENT: 'totalPacketsSent',
        ObjectTypes.PEAK_BYTES_PER_SECOND: 'peakBPS',
        ObjectTypes.PEAK_PACKETS_PER_SECOND: 'peakPPS',
        ObjectTypes.SOURCE_PORT: 'sourcePort',
        ObjectTypes.DEST_PORT: 'destinationPort',
        ObjectTypes.PROTOCOL: 'protocol'
    }
    event_counter = 1
    current_time = datetime.now()
    for event in events:
        timestamp = event.get('timestamp', None)
        if not timestamp:
            raise Exception("'timestamp' field missing from event.")
        try:
            datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            raise Exception("'timestamp' field is not a properly formatted date-time string.")
        title = "IP:[" + ip_address + "],Time:[" + current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ') +\
                "],Event:" + str(event_counter)
        add_event_result = add_new_event(title=title,
                                         description='',
                                         event_type=EventTypes.DISTRIBUTED_DENIAL_OF_SERVICE,
                                         source=source,
                                         method='',
                                         reference='',
                                         date=datetime.now(),
                                         analyst=analyst,
                                         related_id=ip_object_id,
                                         related_type='IP',
                                         relationship_type=RelationshipTypes.RELATED_TO
                                         )
        if not add_event_result['success']:
            raise Exception('Failed to add event for IP object: ' + add_event_result.message)
        new_event_object = Event.objects(id=add_event_result['id']).first()

        for object_type, field_name in object_types_to_field_names.items():
            if field_name in event:
                new_event_object.add_object(object_type=object_type,
                                            value=str(event[field_name]),
                                            source=source,
                                            method='',
                                            reference='',
                                            analyst=analyst
                                            )
        if 'attackTypes' in event:
            # Handle Attack Types differently because this is an array field. Add an Attack Type object for each value.
            attack_types = event['attackTypes']
            for atk_type in attack_types:
                if not isinstance(atk_type, basestring):
                    raise TypeError("The type of one value in 'attackTypes' is not a string.")
                new_event_object.add_object(object_type=ObjectTypes.ATTACK_TYPE,
                                            value=atk_type,
                                            source=source,
                                            method='',
                                            reference='',
                                            analyst=analyst
                                            )
        new_event_object.save(username=analyst)
        event_counter += 1
