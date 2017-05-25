from crits.core.crits_mongoengine import create_embedded_source
from crits.core.handlers import add_releasability, add_releasability_instance
from crits.core.user_tools import get_user_organization
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
        as_number = update_asn_information(ip_object)
        add_owning_source_to_ip(ip_object, as_number)
        update_geoip_information(ip_object)
        ip_object.set_status(Status.ANALYZED)
        # TODO: Potential looping problem because saving data to IP will add another entry to the audit_log.
        ip_object.save(username=analyst)
    except Exception as e:
        raise
    return


def update_asn_information(ip_object):
    """
    Update all ASN information for the input IP object.
    
    :param ip_object: The IP object whose ASN information we're updating.
    :type ip_object: IP
    :return: str, representing AS Number (this is done because we want to save lookup results for use in next steps)
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
                add_releasability('IP', ip_object.id, source.name, analyst)
                add_releasability_instance('IP', ip_object.id, source.name, analyst)
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
        if not (sub_object_type and sub_object_value):
            return
        # To prevent skipping objects while iterating through IP's sub-objects, store list of objects to remove later.
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