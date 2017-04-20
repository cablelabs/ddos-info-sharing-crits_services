import ipaddress
from pymongo import MongoClient

from crits.ips.handlers import ip_add_update
from crits.vocabulary.objects import ObjectTypes


def ip_address_type(ip):
    """
    Determines the IP version of the input IP address, and returns a respective identifier string.
    
    :param ip: The IP address to analyze.
    :type ip: string
    :return: String indicating the version of the IP address. Is either 'IPv4 Address' or 'IPv6 Address'.
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
    :type analyst: string
    :param source: The source of the POST message for the IP objects.
    :type source: string
    :param ip_objects: A group of IP objects to add or update.
    :type ip_objects: A list of dicts.
    :returns: (nothing.)
    """
    for ip_obj in ip_objects:
        add_or_update_ip_object(analyst, source, ip_obj)


def add_or_update_ip_object(analyst, source, ip_object):
    """
    Adds or updates a single IP object to the database.
    
    :param analyst: The analyst who sent the POST message for the IP object.
    :type analyst: string
    :param source: The source of the POST message for the IP object.
    :type source: string
    :param ip_objects: An IP object to add or update.
    :type ip_objects: dict.
    :returns: (nothing.)
    """
    ip = ip_object.get('IPaddress', None)
    ip_type = ip_address_type(ip)
    if not ip or not ip_type:
        raise Exception('Must provide an IP, IP Type, and Source.')

    # New IP object properties, arranged in the order they appear in our schema.
    additional_fields = {}
    object_types_to_parameter = {
        ObjectTypes.CITY: 'City',
        ObjectTypes.STATE: 'State',
        ObjectTypes.COUNTRY: 'Country',
        ObjectTypes.TOTAL_BYTES_PER_SECOND: 'TotalBPS',
        ObjectTypes.TOTAL_PACKETS_PER_SECOND: 'TotalPPS',
        ObjectTypes.AS_NUMBER: 'SourceASN',
        ObjectTypes.ATTACK_TYPE: 'AttackType',
        ObjectTypes.SOURCE_PORT: 'SourcePort',
        ObjectTypes.DEST_PORT: 'DestinationPort'
    }
    for object_type, parameter in object_types_to_parameter.items():
        additional_fields[object_type] = ip_object.get(parameter, None)

    # Extract latitude and longitude from Extra field
    extra = ip_object.get('Extra', None)
    if extra:
        numbers = extra.split(",", 2)
        if len(numbers) == 2:
            try:
                latitude = float(numbers[0])
                longitude = float(numbers[1])
                # No errors occurred, so we're safe to store values.
                additional_fields[ObjectTypes.LATITUDE] = latitude
                additional_fields[ObjectTypes.LONGITUDE] = longitude
            except (TypeError, ValueError):
                pass

    # Eventually, we may not add to the IP collection, but rather our own DDoS IP object collection.
    # Or we may add to both collections.
    add_to_original_ip_collection = True

    if add_to_original_ip_collection:
        result = ip_add_update(ip,
                               ip_type,
                               source=source,
                               analyst=analyst,
                               additional_fields=additional_fields
                               )
        if not result['success']:
            raise Exception('Failed to add/update IP object: ' + result.message)
        return


### DEPRECATED BELOW HERE ###

# Purpose is to add object to separate collection outside of CRITs database.
def add_to_separate_db(ip_object):
    ip = ip_object.get('IPaddress', None)
    ip_type = ip_address_type(ip)
    if not ip or not ip_type:
        raise Exception('Must provide an IP, IP Type, and Source.')

    method = ip_object.get('method', None)
    reference = ip_object.get('reference', None)
    campaign = ip_object.get('campaign', None)
    confidence = ip_object.get('confidence', None)
    add_indicator = ip_object.get('add_indicator', False)
    indicator_reference = ip_object.get('indicator_reference', None)
    bucket_list = ip_object.get('bucket_list', None)
    ticket = ip_object.get('ticket', None)

    # New IP object properties, arranged in the order they appear in our schema.
    first_seen = ip_object.get('FirstSeen', None)
    last_seen = ip_object.get('LastSeen', None)
    number_of_times = ip_object.get('NumberOfTimes', None)
    city = ip_object.get('City', None)
    state = ip_object.get('State', None)
    country = ip_object.get('Country', None)
    total_bps = ip_object.get('TotalBPS', None)
    total_pps = ip_object.get('TotalPPS', None)
    as_number = ip_object.get('SourceASN', None)
    attack_type = ip_object.get('AttackType', None)
    alert_type = ip_object.get('AlertType', None)
    try:
        client = MongoClient('localhost', 27017)
        db = client.data_ingest_ip_info
        collection = db.ips
        ip_data = {
            "ip": ip,
            "ip_type": ip_type,
            "method": method,
            "reference": reference,
            "campaign": campaign,
            "confidence": confidence,
            "add_indicator": add_indicator,
            "indicator_reference": indicator_reference,
            "bucket_list": bucket_list,
            "ticket": ticket,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "number_of_times": number_of_times,
            "city": city,
            "state": state,
            "country": country,
            "total_bps": total_bps,
            "total_pps": total_pps,
            "as_number": as_number,
            "attack_type": attack_type,
            "alert_type": alert_type
        }
        collection.insert(ip_data)
    except Exception as e:
        raise Exception("Failed to add/update DDoS IP object: " + str(e))