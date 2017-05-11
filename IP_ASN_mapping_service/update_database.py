from crits.core.crits_mongoengine import create_embedded_source
from crits.core.handlers import add_releasability, add_releasability_instance
from crits.core.user_tools import get_user_organization
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.status import Status
from GeoIPLookup.GeoIPLookupData import GeoIPLookupData

# Global variables
analyst = "analysis_autofill"


def update_ip_object(ip_object, as_number, as_name, source_name):
    """
    Update the input IP object based on the other inputs.
    
    :param ip_object: The IP object to update.
    :type ip_object: IP
    :param as_number: The value to use for the AS Number of this IP object.
    :type as_number: str
    :param as_name: The value to use for the AS Name of this IP object.
    :type as_name: str
    :param source_name: The name of the source that this IP object should be associated with.
    :type source_name: str
    :return: (nothing)
    """
    global analyst
    update_ip_object_sub_object(ip_object, ObjectTypes.AS_NUMBER, as_number)
    update_ip_object_sub_object(ip_object, ObjectTypes.AS_NAME, as_name)
    add_source_to_ip(ip_object, source_name)
    update_geoip_information(ip_object)
    ip_object.set_status(Status.ANALYZED)
    # TODO: Potential looping problem because saving data to IP will add another entry to the audit_log.
    ip_object.save(username=analyst)
    return


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
    return


def add_source_to_ip(ip_object, source_name):
    """
    Add the source with the input name to the IP object's list of sources, if it is not already there.
    Assumes that source exists in source database.
    
    :param ip_object:
    :type ip_object: IP
    :param source_name:
    :type source_name: str
    :return: (nothing)
    """
    global analyst
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


def update_geoip_information(ip_object):
    """
    Set the City, State, Country, Latitude, and Longitude of the input IP object.
    
    :param ip_object: The IP object to update.
    :type ip_object: IP
    :return: (nothing)
    """
    geoip_lookup_data = GeoIPLookupData(ip_object.ip)
    if geoip_lookup_data:
        if geoip_lookup_data.country:
            update_ip_object_sub_object(ip_object, ObjectTypes.COUNTRY, str(geoip_lookup_data.country))
        if geoip_lookup_data.city:
            update_ip_object_sub_object(ip_object, ObjectTypes.CITY, str(geoip_lookup_data.city))
        if geoip_lookup_data.latitude:
            update_ip_object_sub_object(ip_object, ObjectTypes.LATITUDE, str(geoip_lookup_data.latitude))
        if geoip_lookup_data.longitude:
            update_ip_object_sub_object(ip_object, ObjectTypes.LONGITUDE, str(geoip_lookup_data.longitude))
        if geoip_lookup_data.state:
            update_ip_object_sub_object(ip_object, ObjectTypes.STATE, str(geoip_lookup_data.state))