from ASNLookupData import ASNLookupData

def get_as_number(ip, ip_type):
    lookup_data = ASNLookupData(ip, ip_type)
    return lookup_data.as_number

def get_as_name(ip, ip_type):
    lookup_data = ASNLookupData(ip, ip_type)
    return lookup_data.as_name

def get_country_code(ip, ip_type):
    lookup_data = ASNLookupData(ip, ip_type)
    return lookup_data.country_code

def get_domain(ip, ip_type):
    lookup_data = ASNLookupData(ip, ip_type)
    return lookup_data.domain

def get_isp_name(ip, ip_type):
    lookup_data = ASNLookupData(ip, ip_type)
    return lookup_data.isp