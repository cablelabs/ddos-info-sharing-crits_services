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
            self.city = geoip_lookup_data.get('city')
            self.country = geoip_lookup_data.get('country')
            self.latitude = geoip_lookup_data.get('latitude')
            self.longitude = geoip_lookup_data.get('longitude')
            self.state = geoip_lookup_data.get('state')
        except Exception as e:
            return
