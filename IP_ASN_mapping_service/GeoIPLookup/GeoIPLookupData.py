from maxmind_geoip_lookup import get_geoip_lookup_data_from_geoip2

class GeoIPLookupData:

    def __init__(self, ip_address):
        if not isinstance(ip_address, basestring):
            raise TypeError("Parameter 'ip_address' must be a string.")
        self.city = None
        self.country = None
        self.latitude = None
        self.longitude = None
        self.state = None
        try:
            geoip_lookup_data = get_geoip_lookup_data_from_geoip2(ip_address)
            if 'city' in geoip_lookup_data:
                self.city = geoip_lookup_data['city']
            if 'country' in geoip_lookup_data:
                self.country = geoip_lookup_data['country']
            if 'latitude' in geoip_lookup_data:
                self.latitude = geoip_lookup_data['latitude']
            if 'longitude' in geoip_lookup_data:
                self.longitude = geoip_lookup_data['longitude']
            if 'state' in geoip_lookup_data:
                self.state = geoip_lookup_data['state']
        except Exception as e:
            pass