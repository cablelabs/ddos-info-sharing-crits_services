import commands

class DnsLookupData:
    """Class that stores data from a DNS Lookup. Initialized by doing a DNS Lookup on a particular IP.
    Significant fields from DNS Lookup:
    self.as_number: AS Number of region IP resides in.
    self.as_name: AS Name of source that owns the IP.
    self.country_code: Country Code of region IP resides in.
    self.domain: Domain
    self.isp: ISP
    """
    def __init__(self, ip, ip_type):
        """
        Initialize object using data from DNS Lookup.
        :param ip: IP address to look for, as a string.
        :param ip_type: The type of the IP address to look for, as a string.
        """
        self.dns_lookup(ip, ip_type)

    def dns_lookup(self, ip, ip_type):
        """
        Lookup the AS Number, AS Name, and Country Code for the given IP using a DNS Lookup service.
        :param ip: IP address to look for, as a string.
        :param ip_type: The type of the IP address to look for, as a string.
        :return:
        """
        ip_numbers = ip.split('.')
        # Need to reverse the sections of the IP in order to make the correct request for this IP.
        ip_numbers.reverse()
        reversed_ip = '.'.join(ip_numbers)
        if ip_type == 'IPv4 Address':
            output = commands.getstatusoutput("dig +short " + reversed_ip + ".origin.asn.shadowserver.org TXT")
        else:
            # TODO Figure out how to convert IPv6 address to 'nibble' format. Also, not sure if Shadowserver URL similar.
            output = commands.getstatusoutput("dig +short " + reversed_ip + ".origin6.asn.cymru.com TXT")

        output_fields = output[1].split("|")
        # Values of output_fields should have following indices:
        # AS Number: 0
        # AS Name: 2
        # Country Code: 3
        # Domain: 4
        # ISP: 5
        self.as_number = self.str_minus_extra_characters(output_fields[0])
        self.as_name = self.str_minus_extra_characters(output_fields[2])
        self.country_code = self.str_minus_extra_characters(output_fields[3])
        self.domain = self.str_minus_extra_characters(output_fields[4])
        self.isp = self.str_minus_extra_characters(output_fields[5])
        return

    def str_minus_extra_characters(self, str):
        return str.strip().replace("\"", "")