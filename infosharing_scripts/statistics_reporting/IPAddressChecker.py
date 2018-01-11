import ipaddress


class IPAddressChecker:

    def __init__(self):
        self.invalid_ip_blocks = [
            ipaddress.ip_network(u'0.0.0.0/8'),  # IANA Local Identification Block
            ipaddress.ip_network(u'8.8.4.4/32'),  # Google Anycast DNS address
            ipaddress.ip_network(u'8.8.8.8/32'),  # Google Anycast DNS address
            ipaddress.ip_network(u'10.0.0.0/8'),  # Private address space
            ipaddress.ip_network(u'100.0.0.0/8'),  # Private address space
            ipaddress.ip_network(u'127.0.0.0/8'),  # Loopback block
            ipaddress.ip_network(u'169.254.0.0/16'),
            ipaddress.ip_network(u'172.16.0.0/12'),
            ipaddress.ip_network(u'192.0.0.0/24'),
            ipaddress.ip_network(u'192.0.2.0/24'),
            ipaddress.ip_network(u'192.168.0.0/16'),
            ipaddress.ip_network(u'198.18.0.0/15'),
            ipaddress.ip_network(u'198.51.100.0/24'),
            ipaddress.ip_network(u'203.0.113.0/24'),
            ipaddress.ip_network(u'208.67.222.222/32'),  # OpenDNS
            ipaddress.ip_network(u'224.0.0.0/4'),  # Multicast block (plus other IPs someone suggested blocking)
            ipaddress.ip_network(u'225.0.0.0/8'),  # Multicast block
            ipaddress.ip_network(u'240.0.0.0/4')
        ]

    def is_valid_ip(self, ip_address):
        ip_address_object = ipaddress.ip_address(ip_address)
        for block in self.invalid_ip_blocks:
            if ip_address_object in block:
                return False
        return True
