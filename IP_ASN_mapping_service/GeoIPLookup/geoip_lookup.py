from maxmind_geoip_lookup import get_city_from_geoip2, get_coordinates_from_geoip2,\
    get_country_from_geoip2, get_state_from_geoip2

def get_coordinates(ip_address):
    """
    Get coordinates of IP address.
    :param ip_address:
    :type ip_address: string
    :return: 2-tuple of latitude and longitude as floats, or None if no data is found for this IP.
    """
    return get_coordinates_from_geoip2(ip_address)

def get_latitude(ip_address):
    """
    Return latitude of IP address, if data available.
    :param ip_address:
    :type ip_address: string
    :return: float, or None if no data is found for this IP.
    """
    result = get_coordinates(ip_address)
    if result:
        latitude = result[0]
        return latitude
    return None

def get_longitude(ip_address):
    """
    Return longitude of IP address, if data available.
    :param ip_address:
    :type ip_address: string
    :return: float, or None if no data is found for this IP.
    """
    result = get_coordinates(ip_address)
    if result:
        longitude = result[1]
        return longitude
    return None

def get_city(ip_address):
    """
    Return city of IP address, if data available.
    :param ip_address:
    :type ip_address: string
    :return: string
    """
    return get_city_from_geoip2(ip_address)

def get_country(ip_address):
    """
    Return country of IP address, if data available.
    :param ip_address:
    :type ip_address: string
    :return: string
    """
    return get_country_from_geoip2(ip_address)

def get_state(ip_address):
    """
    Return state (i.e. location) of IP address, if data available.
    :param ip_address:
    :type ip_address: string
    :return: string
    """
    return get_state_from_geoip2(ip_address)