import ipaddress
import pendulum
from pymongo import MongoClient
from crits.core.crits_mongoengine import create_embedded_source
from crits.core.handlers import add_releasability, add_releasability_instance
from crits.core.source_access import SourceAccess
from crits.core.user_tools import get_user_organization
from crits.events.event import Event
from crits.events.handlers import add_new_event
from crits.ips.handlers import ip_add_update
from crits.ips.ip import IP
from crits.vocabulary.events import EventTypes
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.status import Status
from data_ingester_service.vocabulary import IngestFields
from data_ingester_service.handlers import aggregate_event_data
from ASNLookup.ASNLookupData import ASNLookupData
from GeoIPLookup.GeoIPLookupData import GeoIPLookupData


def process_ip_entry(aggregate_ip_entry):
    # TODO: figure out how to handle errors in this function
    save_data_to_crits(aggregate_ip_entry)
    ip_address = aggregate_ip_entry.get('_id', '')
    analyze_and_update_ip(ip_address)
    return


def save_data_to_crits(aggregate_ip_entry):
    last_time_received = None
    ip_address = aggregate_ip_entry.get('_id', '')
    print "Processing data for IP '" + ip_address + "'."
    for event in aggregate_ip_entry['events']:
        analyst = event.get('analyst')
        for db_event in aggregate_event_data(username=analyst):
            for field_name in IngestFields.api_field_names():
                input_value = event.get(field_name)
                db_value = db_event.get(field_name)
                variable_type = IngestFields.api_field_to_variable_type(field_name)
                if variable_type == 'array' and set(input_value) != set(db_value):
                    # Array variable not equal
                    break
                elif input_value != db_value:
                    # Non-array variable not equal
                    break
            else:
                # All variables match, so duplicate Event exists in database.
                break
        else:
            source = event.get('source')
            time_received = event.get('timeReceived')
            if last_time_received is None:
                last_time_received = time_received
            else:
                last_time_received = max(last_time_received, time_received)
            title = "IP:[" + ip_address + "],Time:[" + time_received.strftime('%Y-%m-%dT%H:%M:%S.%fZ') + "]"
            print "Adding new Event for IP '" + ip_address + "'."
            add_event_result = add_new_event(title=title,
                                             description='',
                                             event_type=EventTypes.DISTRIBUTED_DENIAL_OF_SERVICE,
                                             source=source,
                                             method='',
                                             reference='',
                                             date=time_received,
                                             analyst=analyst
                                             )
            event_id = add_event_result['id']
            event_object = Event.objects(id=event_id).first()
            for field_name, field_value in event.iteritems():
                try:
                    object_type = IngestFields.to_object_type(field_name)
                    variable_type = IngestFields.api_field_to_variable_type(field_name)
                except ValueError:
                    continue
                if variable_type == 'array':
                    for item in field_value:
                        event_object.add_object(object_type=object_type,
                                                value=item,
                                                source=source,
                                                method='',
                                                reference='',
                                                analyst=analyst
                                                )
                else:
                    event_object.add_object(object_type=object_type,
                                            value=str(field_value),
                                            source=source,
                                            method='',
                                            reference='',
                                            analyst=analyst
                                            )
            event_object.save(username=analyst)
            ip_type = ip_address_type(ip_address)
            print "Updating IP '" + ip_address + "'."
            update_ip_result = ip_add_update(ip_address=ip_address,
                                             ip_type=ip_type,
                                             source=source,
                                             analyst=analyst,
                                             related_id=event_id,
                                             related_type='Event',
                                             relationship_type=RelationshipTypes.RELATED_TO
                                             )
    update_ip_object_additional_fields(ip_address, last_time_received)


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


def update_ip_object_additional_fields(ip_address, last_time_received=None):
    is_last_time_received_present = False
    is_number_of_times_seen_present = False
    if last_time_received is None:
        last_time_received = pendulum.now('UTC')
    ip_object = IP.objects(ip=ip_address).first()
    number_of_times_seen_str = str(len(ip_object.relationships))
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.LAST_TIME_RECEIVED:
            previous_value = o.value
            previous_value_datetime = pendulum.strptime(previous_value, '%Y-%m-%dT%H:%M:%S.%fZ')
            last_time_received = max(previous_value_datetime, last_time_received)
            last_time_received_str = last_time_received.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            o.value = last_time_received_str
            is_last_time_received_present = True
        elif o.object_type == ObjectTypes.NUMBER_OF_TIMES_SEEN:
            o.value = number_of_times_seen_str
            is_number_of_times_seen_present = True
    # Create new sub-objects for types that were not present.
    autofill_analyst = 'analysis_autofill'
    autofill_source = get_user_organization(autofill_analyst)
    if not is_last_time_received_present:
        last_time_received_str = last_time_received.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        ip_object.add_object(ObjectTypes.LAST_TIME_RECEIVED, last_time_received_str, autofill_source, '', '', autofill_analyst)
    if not is_number_of_times_seen_present:
        ip_object.add_object(ObjectTypes.NUMBER_OF_TIMES_SEEN, number_of_times_seen_str, autofill_source, '', '', autofill_analyst)
    ip_object.set_status(Status.IN_PROGRESS)
    ip_object.save(username=autofill_analyst)


def analyze_and_update_ip(ip_address):
    """
    Analyze the input IP address' object, and update it based on lookup information.
    :param ip_address: The IP address of the object to update.
    :type ip_address: str
    :return: (nothing)
    """
    ip_object = IP.objects(ip=ip_address).first()
    update_event_aggregate_fields(ip_object)
    as_number = update_asn_information(ip_object)
    add_owning_source_to_ip(ip_object, as_number)
    update_reporter_fields(ip_object)
    update_geoip_information(ip_object)
    ip_object.set_status(Status.ANALYZED)
    autofill_analyst = 'analysis_autofill'
    ip_object.save(username=autofill_analyst)
    return


def update_event_aggregate_fields(ip_object):
    """
    Update fields that are the result of aggregating data from multiple events.
    :param ip_object: The IP object to update.
    :type ip_object: IP
    :return: (nothing)
    """
    total_bytes_sent = 0
    total_packets_sent = 0
    aggregate_bytes_per_second = 0
    aggregate_packets_per_second = 0
    for relationship in ip_object.relationships:
        if relationship.rel_type == 'Event':
            event_id = relationship.object_id
            event = Event.objects(id=event_id).first()
            if event:
                for obj in event.obj:
                    if obj.object_type == ObjectTypes.TOTAL_BYTES_SENT:
                        try:
                            total_bytes_sent += int(obj.value)
                        except (TypeError, ValueError):
                            continue
                    elif obj.object_type == ObjectTypes.TOTAL_PACKETS_SENT:
                        try:
                            total_packets_sent += int(obj.value)
                        except (TypeError, ValueError):
                            continue
                    elif obj.object_type == ObjectTypes.PEAK_BYTES_PER_SECOND:
                        try:
                            aggregate_bytes_per_second += int(obj.value)
                        except (TypeError, ValueError):
                            continue
                    elif obj.object_type == ObjectTypes.PEAK_PACKETS_PER_SECOND:
                        try:
                            aggregate_packets_per_second += int(obj.value)
                        except (TypeError, ValueError):
                            continue
    update_ip_object_sub_object(ip_object, ObjectTypes.TOTAL_BYTES_SENT, str(total_bytes_sent))
    update_ip_object_sub_object(ip_object, ObjectTypes.TOTAL_PACKETS_SENT, str(total_packets_sent))
    update_ip_object_sub_object(ip_object, ObjectTypes.AGGREGATE_BYTES_PER_SECOND, str(aggregate_bytes_per_second))
    update_ip_object_sub_object(ip_object, ObjectTypes.AGGREGATE_PACKETS_PER_SECOND, str(aggregate_packets_per_second))


def update_asn_information(ip_object):
    """
    Update all ASN information for the input IP object.
    :param ip_object: The IP object whose ASN information we're updating.
    :type ip_object: IP
    :return: str, representing AS Number (which is used in next step of updating IP)
    """
    asn_lookup_data = ASNLookupData(ip_object.ip)
    if asn_lookup_data:
        if asn_lookup_data.as_number:
            update_ip_object_sub_object(ip_object, ObjectTypes.AS_NUMBER, asn_lookup_data.as_number)
        if asn_lookup_data.as_name:
            update_ip_object_sub_object(ip_object, ObjectTypes.AS_NAME, asn_lookup_data.as_name)
        return asn_lookup_data.as_number
    return ''


def add_owning_source_to_ip(ip_object, as_number):
    """
    Add the source associated with the input AS Number to the IP object's list of sources, if the source exists and is
    not already associated with the IP.
    :param ip_object: The IP object whose sources may be updated.
    :type ip_object: IP
    :param as_number: The AS Number that should be associated with the source we may add.
    :type as_number: str
    :return: (nothing)
    """
    try:
        as_number_int = int(as_number)
    except (TypeError, ValueError):
        return
    source = SourceAccess.objects(asns=as_number_int).first()
    if source:
        for src in ip_object.source:
            if src.name == source.name:
                # Source already in IP's sources
                # TODO: should I still check for a releasability instance?
                return
        autofill_analyst = 'analysis_autofill'
        new_ip_source = create_embedded_source(source.name, analyst=autofill_analyst)
        if new_ip_source:
            # TODO: Does this line and save() on IP result in two source instances whose analyst is "analysis_autofill"?
            ip_object.add_source(new_ip_source)
            # Add a brand new releasability, and add an instance to that releasability.
            add_releasability('IP', ip_object.id, new_ip_source.name, autofill_analyst)
            add_releasability_instance('IP', ip_object.id, new_ip_source.name, autofill_analyst)
    return


def update_reporter_fields(ip_object):
    """
    Update fields related to the reporters of the IP, including the number of reporters, and the name of all reporters.
    :param ip_object: The IP object to update.
    :type ip_object: IP
    :return: (nothing)
    """
    # Step 1: Remove all previous "Reported By" sub-objects.
    # To prevent skipping objects while iterating through sub-objects, store list of objects to remove later.
    previous_object_values = []
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.REPORTED_BY:
            previous_object_values.append(o.value)
    for previous_value in previous_object_values:
        ip_object.remove_object(ObjectTypes.REPORTED_BY, previous_value)
    # Step 2: Determine which sources are reporters by finding all Events reported for the IP.
    # Note: This is not calculated from IP's sources because those are not removed when Events are removed.
    source_names = []
    for relationship in ip_object.relationships:
        if relationship.rel_type == 'Event':
            event_id = relationship.object_id
            event_object = Event.objects(id=event_id).first()
            for src in event_object['source']:
                if src.name not in source_names:
                    source_names.append(src.name)
    # Step 3: Update the appropriate sub-objects in the IP object.
    autofill_analyst = 'analysis_autofill'
    for reporter in source_names:
        # Don't use my wrapper function to update sub-object, because the goal is to save each reporter name.
        ip_object.add_object(ObjectTypes.REPORTED_BY, reporter, get_user_organization(autofill_analyst), '', '', autofill_analyst)
    number_of_reporters_str = str(len(source_names))
    update_ip_object_sub_object(ip_object, ObjectTypes.NUMBER_OF_REPORTERS, number_of_reporters_str)


def update_geoip_information(ip_object):
    """
    Set the City, State, Country, Latitude, and Longitude of the input IP object.
    :param ip_object: The IP object to update.
    :type ip_object: IP
    :return: (nothing)
    """
    geoip_lookup_data = GeoIPLookupData(ip_object.ip)
    if geoip_lookup_data:
        if geoip_lookup_data.city:
            update_ip_object_sub_object(ip_object, ObjectTypes.CITY, geoip_lookup_data.city)
        if geoip_lookup_data.country:
            update_ip_object_sub_object(ip_object, ObjectTypes.COUNTRY, geoip_lookup_data.country)
        if geoip_lookup_data.latitude:
            update_ip_object_sub_object(ip_object, ObjectTypes.LATITUDE, geoip_lookup_data.latitude)
        if geoip_lookup_data.longitude:
            update_ip_object_sub_object(ip_object, ObjectTypes.LONGITUDE, geoip_lookup_data.longitude)
        if geoip_lookup_data.state:
            update_ip_object_sub_object(ip_object, ObjectTypes.STATE, geoip_lookup_data.state)


def update_ip_object_sub_object(ip_object, sub_object_type, sub_object_value):
    """
    For the input IP object, set the sub-object of the input type to the input value, removing all previous values.
    :param ip_object: The IP object to update.
    :type ip_object: IP
    :param sub_object_type: The type of the sub-object to update.
    :type sub_object_type: str
    :param sub_object_value: The value to which the sub-object will be set.
    :type sub_object_value: str
    :return: (nothing)
    """
    autofill_analyst = 'analysis_autofill'
    if sub_object_type and sub_object_value:
        # To prevent skipping objects while iterating through sub-objects, store list of objects to remove later.
        previous_object_values = []
        for o in ip_object.obj:
            if o.object_type == sub_object_type:
                previous_object_values.append(o.value)
        for previous_value in previous_object_values:
            ip_object.remove_object(sub_object_type, previous_value)
        ip_object.add_object(sub_object_type, sub_object_value, get_user_organization(autofill_analyst), '', '', autofill_analyst)
    return
