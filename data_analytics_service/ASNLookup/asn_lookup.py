from dns_asn_lookup import get_asn_data
from ipwhois_asn_lookup import get_as_number_from_ipwhois, get_country_code_from_ipwhois
from rdap_asn_lookup import get_as_name_from_rdap


def get_as_number(ip_address):
    if not isinstance(ip_address, basestring):
        raise TypeError("Parameter 'ip_address' must be a string.")
    return get_as_number_from_ipwhois(ip_address)


def get_as_name(ip_address):
    if not isinstance(ip_address, basestring):
        raise TypeError("Parameter 'ip_address' must be a string.")
    return get_as_name_from_rdap(ip_address)


def get_country_code(ip_address):
    if not isinstance(ip_address, basestring):
        raise TypeError("Parameter 'ip_address' must be a string.")
    return get_country_code_from_ipwhois(ip_address)


def get_isp_name(ip_address):
    if not isinstance(ip_address, basestring):
        raise TypeError("Parameter 'ip_address' must be a string.")
    # TODO: If we actually use this function, make sure it can handle IPv6.
    asn_data = get_asn_data(ip_address, 'IPv4 Address')
    if 'isp' in asn_data:
        return asn_data['isp']
    return ''
