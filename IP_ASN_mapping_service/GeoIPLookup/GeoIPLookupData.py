from maxmind_geoip_lookup import get_geoip_lookup_data_from_geoip2

class GeoIPLookupData:

    def __init__(self, ip_address):
        if not isinstance(ip_address, basestring):
            raise TypeError("Parameter 'ip_address' must be a string.")
        try:
            geoip_lookup_data = get_geoip_lookup_data_from_geoip2(ip_address)
            self.city = geoip_lookup_data['city']
            self.country = geoip_lookup_data['country']
            self.latitude = geoip_lookup_data['latitude']
            self.longitude = geoip_lookup_data['longitude']
            self.state = geoip_lookup_data['state']
        except Exception as e:
            self.city = None
            self.country = None
            self.latitude = None
            self.longitude = None
            self.state = None