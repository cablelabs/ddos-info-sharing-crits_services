from datetime import datetime
import ipaddress

from crits.events.event import Event
from crits.events.handlers import add_new_event
from crits.ips.ip import IP
from crits.ips.handlers import ip_add_update
from crits.vocabulary.events import EventTypes
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.status import Status


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
        ip_object = IP.objects(ip=ip_address).first()
        if ip_object:
            ip_object.set_status(Status.NEW)
            #print "Ingester: Resetting status of IP '" + ip_address + "' to 'New'."
            ip_object.save(username=analyst)
            #print "Ingester: Done resetting status."
        ip_type = ip_address_type(ip_address)
        #print "Ingester: Add/update to IP '" + ip_address + "'."
        result = ip_add_update(ip_address=ip_address, ip_type=ip_type, source=source, analyst=analyst)
        #print "Ingester: Done with add/update."
        if not result['success']:
            raise Exception(result['message'])
        save_new_event(analyst, source, ingest_data_entry)
        update_ip_object_additional_fields(analyst, source, ip_address)


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


def save_new_event(analyst, source, ingest_data_entry):
    """
    Save relevant information from ingest data into a new event associated with the IP address.
    
    :param analyst: The analyst who sent the POST message for the IP object.
    :type analyst: str
    :param source: The source of the POST message for the IP object.
    :type source: str
    :param ingest_data_entry: An object with data about attacks from the IP address.
    :type ingest_data_entry: dict, conforming to an 'ingestData' object in the definitions of the data ingester payload schema
    :return: (nothing)
    """
    ip_address = ingest_data_entry.get('IPaddress')
    ip_object = IP.objects(ip=ip_address).first()
    ip_object_id = ip_object.id
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
    # Add an Attack Type object for each value from input.
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
    #print "Saving new event for IP '" + ip_address + "'."
    event_object.save(username=analyst)
    #print "Done saving event for IP '" + ip_address + "'."


def update_ip_object_additional_fields(analyst, source, ip_address):
    """
    Updates additional fields for the IP object.

    :param analyst: The analyst who sent the POST message for the IP object.
    :type analyst: str
    :param source: The source of the POST message for the IP object.
    :type source: str
    :param ip_address: The IP address of the IP object to update.
    :type ip_address: str
    :return: (nothing)
    """
    ip_object = IP.objects(ip=ip_address).first()
    is_last_time_received_present = False
    is_number_of_times_seen_present = False
    current_time_string = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.LAST_TIME_RECEIVED:
            o.value = current_time_string
            is_last_time_received_present = True
        elif o.object_type == ObjectTypes.NUMBER_OF_TIMES_SEEN:
            # Increment number of times seen
            try:
                int_value = int(o.value)
                int_value += 1
                o.value = str(int_value)
            except (TypeError, ValueError):
                pass
            is_number_of_times_seen_present = True
    # Create new sub-objects for types that were not present.
    if not is_last_time_received_present:
        ip_object.add_object(ObjectTypes.LAST_TIME_RECEIVED, current_time_string, source, '', '', analyst)
    if not is_number_of_times_seen_present:
        ip_object.add_object(ObjectTypes.NUMBER_OF_TIMES_SEEN, '1', source, '', '', analyst)
    ip_object.set_status(Status.IN_PROGRESS)
    #print "Saving updates to IP '" + ip_object.ip + "' and setting status to 'In Progress'."
    ip_object.save(username=analyst)
    #print "Done saving updates to IP '" + ip_object.ip + "'."
