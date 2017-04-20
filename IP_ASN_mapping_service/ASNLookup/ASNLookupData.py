from dns_asn_lookup import get_asn_data

class ASNLookupData:
    """
    Class that stores data from an ASN Lookup. Initialized by doing a DNS Lookup on a particular IP.
    Significant fields from ASN Lookup:
    self.as_number: AS Number of region IP resides in.
    self.as_name: AS Name of source that owns the IP.
    self.country_code: Country Code of region IP resides in.
    self.domain: Domain
    self.isp: ISP
    """
    def __init__(self, ip, ip_type):
        """
        :param ip: IP address to look for.
        :type ip: string
        :param ip_type: The type of the IP address to look for. If input is not 'IPv4 Address', assumes IP is IPv6.
        :type ip_type: string
        """
        # Initialize object using data from DNS Lookup.
        output = get_asn_data(ip, ip_type)
        self.as_number = output['as_number']
        self.as_name = output['as_name']
        self.country_code = output['country_code']
        self.domain = output['domain']
        self.isp = output['isp']