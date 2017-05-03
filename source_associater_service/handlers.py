from crits.core.crits_mongoengine import create_embedded_source
from crits.core.handlers import add_releasability, add_releasability_instance, get_source_names
from crits.ips.ip import IP
from crits.core.source_access import SourceAccess

def get_all_source_names():
    all_sources = get_source_names()
    all_source_names = []
    for src in all_sources:
        all_source_names.append(src['name'])
    return all_source_names

def associate_ips_to_sources(source_name):
    try:
        if not source_name:
            return False
        source_object = SourceAccess.objects(name=source_name).first()
        asns = [str(x) for x in source_object.asns]
        ip_data_list = get_ip_data_list(asns)
        add_source_to_ips(ip_data_list, source_name)
        return True
    except Exception as e:
        return False

def get_ip_data_list(asns):
    """
    Get list of relevant data on all IPs such that its AS Number is a value in the input list.
    :param asns: List of ASNs, as strings, such that IPs returned contain at least one number.
    :type asns: list
    :return: list, of IP objects with up to three fields: 'IPaddress', 'sources', and 'AS Number'.
    """
    # Remap AS Number to an un-nested field
    as_number_projection = {
        '$let': {
            'vars': {
                'one_obj': {
                    '$arrayElemAt': [
                        {
                            '$filter': {
                                'input': '$objects',
                                'as': 'obj',
                                'cond': {'$eq': ['$$obj.type', "AS Number"]}
                            }
                        },
                        0
                    ]
                }
            },
            'in': '$$one_obj.value'
        }
    }
    project = {
        '$project': {
            '_id': 0,
            'ip': 1,
            'source': 1,
            'ASNumber': as_number_projection
        }
    }
    # Filter on IPs where ASN is in source's ASNs.
    as_number_match = {'$match': {'ASNumber': {'$in': asns}}}
    unwind = {'$unwind': '$source'}
    group = {
        '$group': {
            '_id': '$ip',
            'sources': {
                '$push': '$source.name' # include only the name of each source
            },
            'ASNumber': {
                '$first': '$ASNumber'
            }
        }
    }
    second_project = {
        '$project': {
            '_id': 0,
            'IPaddress': '$_id',
            'sources': 1,
            'ASNumber': 1
        }
    }
    aggregation_pipeline = [project, as_number_match, unwind, group, second_project]
    ip_data_objects = IP.objects.aggregate(*aggregation_pipeline, useCursor=False)
    return list(ip_data_objects)

def add_source_to_ips(ip_data_list, source_name):
    """
    Set source of every IP in list to source_name.
    :param ip_data_list: 
    :param source_name: 
    :return: 
    """
    for ip_data in ip_data_list:
        add_source_to_ip(ip_data, source_name)

def add_source_to_ip(ip_data, source_name):
    """
    Adds a new source to the IP object's list of sources, if it is not already there.
    :param ip_data:
    :param source_name:
    :return:
    """
    if not source_name:
        return
    for src in ip_data['sources']:
        if src == source_name:
            # Source already in IP's sources
            return
    analyst = 'analysis_autofill'
    source = create_embedded_source(source_name, analyst=analyst)
    if source:
        ip_object = IP.objects(ip=ip_data['IPaddress']).first()
        ip_object.add_source(source)
        # Add a brand new releasability, and add an instance to that releasability.
        add_releasability('IP', ip_object.id, source.name, analyst)
        add_releasability_instance('IP', ip_object.id, source.name, analyst)
        ip_object.save()
    return

def is_source_in_ips(ip_data_list, source_name):
    """
    Return true iff source_name is source of every IP in the input list.
    :param ip_object_list: 
    :param source_name: 
    :return: boolean
    """
    if not source_name:
        return False
    for ip_data in ip_data_list:
        found_source = False
        for src in ip_data['sources']:
            if src == source_name:
                found_source = True
                break
        if not found_source:
            return False
    return True