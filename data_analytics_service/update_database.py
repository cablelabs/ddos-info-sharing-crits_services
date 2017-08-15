from crits.core.crits_mongoengine import create_embedded_source
from crits.core.handlers import add_releasability, add_releasability_instance
from crits.core.user_tools import get_user_organization
from crits.events.event import Event
from crits.ips.ip import IP
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.status import Status
from ASNLookup.ASNLookupData import ASNLookupData
from GeoIPLookup.GeoIPLookupData import GeoIPLookupData
from crits.core.source_access import SourceAccess

# Global variables
analyst = "analysis_autofill"


def analyze_and_update_ip_object(ip_object):
    """
    Analyze the input IP object, and update it based on lookup information.
    
    :param ip_object: The IP object to update.
    :type ip_object: IP
    :return: (nothing)
    """
    global analyst
    try:
        ip_address = ip_object.ip
        print "Updating event aggregate fields for IP '" + ip_address + "'."
        update_event_aggregate_fields(ip_object)
        print "Updating ASN information for IP '" + ip_address + "'."
        as_number = update_asn_information(ip_object)
        print "Adding appropriate sources to IP '" + ip_address + "'."
        add_owning_source_to_ip(ip_object, as_number)
        print "Updating reporter fields for IP '" + ip_address + "'."
        update_reporter_fields(ip_object)
        print "Updating geoip information for IP '" + ip_address + "'."
        update_geoip_information(ip_object)
        print "Setting status of IP '" + ip_address + "' to 'Analyzed'."
        ip_object.set_status(Status.ANALYZED)
        print "Saving IP '" + ip_object.ip + "' in data analytics service."
        ip_object.save(username=analyst)
        print "Done saving IP '" + ip_address + "' for data analytics service."
    except Exception as e:
        raise
    return


# TODO: compare performance of this to the method I'm using right now for updating reporter fields
def update_reporter_fields_untested_version(ip_object):
    """
    Update fields regarding the number of reporters and who reported the IP.

    :param ip_object: The IP object to update.
    :type ip_object: IP
    :return: (nothing)
    """
    global analyst
    source_aggregation_pipeline = [
        {'$match': {'ip': ip_object.ip}},
        {'$project': {'_id': 0, 'source': 1}},
        {'$unwind': '$source'},
        {'$group': {'_id': '$ip', 'sources': {'$push': '$source.name'}}},
        {'$project': {'_id': 0, 'sources': 1}}
    ]
    source_aggregation_result = IP.objects.aggregate(*source_aggregation_pipeline, useCursor=False)
    source_names = []
    for item in source_aggregation_result:
        source_names = item['sources']
    releasability_aggregation_pipeline = [
        {'$match': {'ip': ip_object.ip}},
        {'$project': {'_id': 0, 'releasability': 1}},
        {'$unwind': '$releasability'},
        {'$group': {'_id': '$ip', 'releasabilities': {'$push': '$releasability.name'}}},
        {'$project': {'_id': 0, 'releasabilities': 1}}
    ]
    releasability_aggregation_result = IP.objects.aggregate(*releasability_aggregation_pipeline, useCursor=False)
    releasability_names = []
    for item in releasability_aggregation_result:
        releasability_names = item['releasabilities']
    reporter_names_set = set(source_names).difference(set(releasability_names))
    for reporter in reporter_names_set:
        # Don't use my wrapper function to update sub-object, because the goal is to save each reporter name.
        ip_object.add_object(ObjectTypes.REPORTED_BY, reporter, get_user_organization(analyst), '', '', analyst)
    number_of_reporters_str = str(len(reporter_names_set))
    update_ip_object_sub_object(ip_object, ObjectTypes.NUMBER_OF_REPORTERS, number_of_reporters_str)

# TODO: compare performance of these steps to version where I use aggregate on events collection, or aggregate on a single IP object using lookup stage
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
    global analyst
    source_name = get_name_of_source_with_as_number(as_number)
    if source_name:
        try:
            for src in ip_object.source:
                if src.name == source_name:
                    # Source already in IP's sources
                    return
            source = create_embedded_source(source_name, analyst=analyst)
            if source:
                ip_object.add_source(source)
                # Add a brand new releasability, and add an instance to that releasability.
                #print "Adding releasability to IP '" + ip_object.ip + "' for source '" + source.name + "'."
                add_releasability('IP', ip_object.id, source.name, analyst)
                #print "Adding releasability instance to IP '" + ip_object.ip + "' for source '" + source.name + "'."
                add_releasability_instance('IP', ip_object.id, source.name, analyst)
                #print "Done adding releasability instance to IP '" + ip_object.ip + "' for source '" + source.name + "'."
        except Exception as e:
            raise
    return


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


# TODO: compare performance to list comprehension and map() function.
def update_reporter_fields(ip_object):
    """
    Update fields related to the reporters of the IP, including the number of reporters, and the name of all reporters.

    :param ip_object: The IP object to update.
    :type ip_object: IP
    :return: (nothing)
    """
    global analyst
    # First, remove all previous "Reported By" sub-objects.
    # To prevent skipping objects while iterating through sub-objects, store list of objects to remove later.
    previous_object_values = []
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.REPORTED_BY:
            previous_object_values.append(o.value)
    for previous_value in previous_object_values:
        ip_object.remove_object(ObjectTypes.REPORTED_BY, previous_value)

    # Second, determine which sources are reporters by excluding those that have a releasability.
    # Obtain latest copy of IP object so the new releasability, if any, is accounted for.
    current_ip_object = IP.objects(id=ip_object.id).first()
    source_names = [x['name'] for x in current_ip_object['source']]
    releasability_names = [x['name'] for x in current_ip_object['releasability']]
    reporter_names_set = set(source_names).difference(set(releasability_names))

    # Finally, update the appropriate sub-objects in the IP object.
    for reporter in reporter_names_set:
        # Don't use my wrapper function to update sub-object, because the goal is to save each reporter name.
        ip_object.add_object(ObjectTypes.REPORTED_BY, reporter, get_user_organization(analyst), '', '', analyst)
    number_of_reporters_str = str(len(reporter_names_set))
    update_ip_object_sub_object(ip_object, ObjectTypes.NUMBER_OF_REPORTERS, number_of_reporters_str)


def update_geoip_information(ip_object):
    """
    Set the City, State, Country, Latitude, and Longitude of the input IP object.
    
    :param ip_object: The IP object to update.
    :type ip_object: IP
    :return: (nothing)
    """
    try:
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
    except Exception as e:
        raise


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
    global analyst
    try:
        if sub_object_type and sub_object_value:
            # To prevent skipping objects while iterating through sub-objects, store list of objects to remove later.
            previous_object_values = []
            for o in ip_object.obj:
                if o.object_type == sub_object_type:
                    previous_object_values.append(o.value)
            for previous_value in previous_object_values:
                ip_object.remove_object(sub_object_type, previous_value)
            ip_object.add_object(sub_object_type, sub_object_value, get_user_organization(analyst), '', '', analyst)
    except Exception as e:
        raise
    return
