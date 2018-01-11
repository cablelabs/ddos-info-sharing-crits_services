from ipwhois_asn_lookup import get_asn_data_from_ipwhois
from rdap_asn_lookup import get_as_name_from_rdap_using_as_number


class ASNLookupData:
    """
    Class that stores data from an ASN Lookup. Initialized by doing a DNS Lookup on a particular IP.
    Significant fields from ASN Lookup:
    self.as_number: AS Number of region IP resides in.
    self.as_name: AS Name of source that owns the IP.
    self.country_code: Country Code of region IP resides in.
    """
    def __init__(self, ip_address):
        """
        :param ip: IP address to look for.
        :type ip: string
        """
        if not isinstance(ip_address, basestring):
            raise TypeError("Parameter 'ip_address' must be a string.")
        self.as_number = None
        self.as_name = None
        # Initialize object using data from DNS Lookup.
        try:
            asn_data = get_asn_data_from_ipwhois(ip_address)
        except Exception as e:
            return
        if asn_data and 'as_number' in asn_data:
            self.as_number = asn_data['as_number']
            try:
                self.as_name = get_as_name_from_rdap_using_as_number(self.as_number)
            except Exception as e:
                return
