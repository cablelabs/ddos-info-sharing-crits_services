from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError, HTTPLookupError

def get_asn_data_from_ipwhois(ip_address):
    result = get_rdap_lookup_result(ip_address)
    output = {
        'as_number': result['asn'],
        'country_code': result['asn_country_code']
    }
    return output

def get_as_number_from_ipwhois(ip_address):
    result = get_rdap_lookup_result(ip_address)
    return result['asn']

def get_country_code_from_ipwhois(ip_address):
    result = get_rdap_lookup_result(ip_address)
    return result['country_code']

def get_rdap_lookup_result(ip_address):
    object = IPWhois(ip_address)
    try:
        result = object.lookup_rdap(depth=1)
    except ValueError:
        raise
    except IPDefinedError:
        raise ValueError("IP address " + ip_address + " is reserved for some special purpose.")
    except ASNRegistryError:
        raise ValueError("IP address " + ip_address + " does not have entry in ASN registry.")
    except HTTPLookupError as e:
        raise Exception(e.message)
    return result