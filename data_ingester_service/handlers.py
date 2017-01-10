from crits.ips.handlers import ip_add_update
from pymongo import MongoClient

import ipaddress


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

    add_to_original_ip_collection = True

    if add_to_original_ip_collection:
        result = ip_add_update(ip,
                               ip_type,
                               source=source,
                               source_method=method,
                               source_reference=reference,
                               campaign=campaign,
                               confidence=confidence,
                               analyst=analyst,
                               bucket_list=bucket_list,
                               ticket=ticket,
                               is_add_indicator=add_indicator,
                               indicator_reference=indicator_reference,
                               alert_type=alert_type,
                               as_number=as_number,
                               attack_type=attack_type,
                               city=city,
                               country=country,
                               first_seen=first_seen,
                               last_seen=last_seen,
                               number_of_times=number_of_times,
                               state=state,
                               total_bps=total_bps,
                               total_pps=total_pps)
        if not result['success']:
            raise Exception('Failed to add/update IP object: ' + result.message)
        return

    # add object to separate collection outside of CRITs database
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