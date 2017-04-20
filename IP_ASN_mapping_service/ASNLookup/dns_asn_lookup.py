import commands

def get_asn_data(ip, ip_type):
    """
    Lookup the AS Number, AS Name, and Country Code for the given IP using a DNS Lookup service.
    :param ip: IP address to look for.
    :type ip: string.
    :param ip_type: The type of the IP address to look for. If input is not 'IPv4 Address', assumes IP is IPv6.
    :type ip_type: string
    :return: dictionary with the following fields: 'as_number', 'as_name', 'country_code', 'domain', 'isp'
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
    output = {}
    output['as_number'] = str_minus_extra_characters(output_fields[0])
    output['as_name'] = str_minus_extra_characters(output_fields[2])
    output['country_code'] = str_minus_extra_characters(output_fields[3])
    output['domain'] = str_minus_extra_characters(output_fields[4])
    output['isp'] = str_minus_extra_characters(output_fields[5])
    return output

def str_minus_extra_characters(str):
    return str.strip().replace("\"", "")