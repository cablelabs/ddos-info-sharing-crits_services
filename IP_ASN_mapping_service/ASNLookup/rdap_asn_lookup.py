import requests

from ipwhois_asn_lookup import get_as_number_from_ipwhois


def get_as_name_from_rdap(ip_address):
    """
    Returns AS Name corresponding to given IP address.
    :param ip_address:
    :type ip_address: string
    :param as_number:
    :type as_number: string
    :return: string
    """
    as_number = get_as_number_from_ipwhois(ip_address)
    return get_as_name_from_rdap_using_as_number(as_number)


def get_as_name_from_rdap_using_as_number(as_number):
    """
    Returns AS Name corresponding to given AS Number.
    :param as_number:
    :type as_number: string
    :return: string
    """
    get_url = 'https://rdap.db.ripe.net/autnum/' + as_number
    response = requests.get(url=get_url)
    response_json = response.json()
    return response_json['name']
