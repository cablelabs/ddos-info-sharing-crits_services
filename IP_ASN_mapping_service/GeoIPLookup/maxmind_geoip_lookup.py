import geoip2, geoip2.database, geoip2.errors

def get_geoip_lookup_data_from_geoip2(ip_address):
    """
    Get all relevant GeoIP data regarding IP address from local GeoIP database.
    :param ip_address:
    :type ip_address: string
    :return: dict, which includes the following fields: 'city', 'country', 'latitude', 'longitude', 'state'
    """
    database_location = '/usr/local/share/GeoIP/GeoLite2-City.mmdb'
    reader = geoip2.database.Reader(database_location)
    lookup_data = {
        'city': None,
        'country': None,
        'latitude': None,
        'longitude': None,
        'state': None
    }
    try:
        response = reader.city(ip_address)
    except geoip2.errors.AddressNotFoundError:
        return lookup_data
    if response:
        if response.location:
            if response.location.latitude:
                lookup_data['latitude'] = response.location.latitude
            if response.location.longitude:
                lookup_data['longitude'] = response.location.longitude
        if response.city and response.city.name:
            lookup_data['city'] = response.city.name
        if response.country and response.country.name:
            lookup_data['country'] = response.country.name
        if response.subdivisions and response.subdivisions.most_specific and response.subdivisions.most_specific.name:
            lookup_data['state'] = response.subdivisions.most_specific.name
    return lookup_data

def get_coordinates_from_geoip2(ip_address):
    """
    Get coordinates of IP address from local GeoIP database.
    :param ip_address:
    :type ip_address: string
    :return: 2-tuple of latitude and longitude as floats, or None if no data is found for this IP.
    """
    database_location = '/usr/local/share/GeoIP/GeoLite2-City.mmdb'
    reader = geoip2.database.Reader(database_location)
    try:
        response = reader.city(ip_address)
    except geoip2.errors.AddressNotFoundError:
        return None
    if (response and response.location and
            response.location.latitude and response.location.longitude):
        return (response.location.latitude, response.location.longitude)
    # Doesn't make sense to return result that is missing latitude and/or longitude
    return None

def get_city_from_geoip2(ip_address):
    """
    Get city of IP address from local GeoIP database.
    :param ip_address:
    :type ip_address: string
    :return: string
    """
    database_location = '/usr/local/share/GeoIP/GeoLite2-City.mmdb'
    reader = geoip2.database.Reader(database_location)
    try:
        response = reader.city(ip_address)
    except geoip2.errors.AddressNotFoundError:
        return None
    if (response and response.city and response.city.name):
        return response.city.name
    return None

def get_country_from_geoip2(ip_address):
    """
    Get country of IP address from local GeoIP database.
    :param ip_address:
    :type ip_address: string
    :return: string
    """
    database_location = '/usr/local/share/GeoIP/GeoLite2-City.mmdb'
    reader = geoip2.database.Reader(database_location)
    try:
        response = reader.city(ip_address)
    except geoip2.errors.AddressNotFoundError:
        return None
    if (response and response.country and response.country.name):
        return response.country.name
    return None

def get_state_from_geoip2(ip_address):
    """
    Get state (i.e. location) of IP address from local GeoIP database.
    :param ip_address:
    :type: ip_address: string
    :return: string
    """
    database_location = '/usr/local/share/GeoIP/GeoLite2-City.mmdb'
    reader = geoip2.database.Reader(database_location)
    try:
        response = reader.city(ip_address)
    except geoip2.errors.AddressNotFoundError:
        return None
    if (response and response.subdivisions and
            response.subdivisions.most_specific and response.subdivisions.most_specific.name):
        return response.subdivisions.most_specific.name
    return None