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
        raise TypeError("Parameter 'ip_address' must be a string")
    return get_country_code_from_ipwhois(ip_address)