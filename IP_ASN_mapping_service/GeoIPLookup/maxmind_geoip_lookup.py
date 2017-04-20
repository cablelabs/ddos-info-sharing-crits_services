import geoip2, geoip2.database, geoip2.errors

def get_coordinates(ip_address):
    """
    Get coordinates of IP address from local GeoIP database.
    :param ip_address:
    :type ip_address: string
    :return: 2-tuple of latitude and longitude as floats, or None if no data is found for this IP.
    """
    reader = geoip2.database.Reader('/usr/local/share/GeoIP/GeoLite2-City.mmdb')
    try:
        response = reader.city(ip_address)
    except geoip2.errors.AddressNotFoundError:
        return None
    if not (response and response.location
            and response.location.latitude and response.location.longitude):
        # Doesn't make sense to return result that is missing latitude and/or longitude
        return None
    return (response.location.latitude, response.location.longitude)