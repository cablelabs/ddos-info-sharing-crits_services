from ipwhois import IPWhois

def get_asn_data_from_ipwhois(ip):
    object = IPWhois(ip)
    result = object.lookup_rdap(depth=1)
    output = {
        'as_number': result['asn'],
        'country_code': result['asn_country_code']
    }
    return output

def get_as_number_from_ipwhois(ip_address):
    object = IPWhois(ip_address)
    result = object.lookup_rdap(depth=1)
    return result['asn']

def get_country_code_from_ipwhois(ip_address):
    object = IPWhois(ip_address)
    result = object.lookup_rdap(depth=1)
    return result['country_code']