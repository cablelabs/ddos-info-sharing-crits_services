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

# TODO: possibly return something indicating success or failure
def associate_ips_to_sources(source_name):
    try:
        if not source_name:
            return False
        source_object = SourceAccess.objects(name=source_name).first()
        asns = [str(x) for x in source_object.asns]

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
        project = {'$project': {'_id': 0, 'IPaddress': '$ip', 'ASNumber': as_number_projection}}
        # Filter on IPs where ASN is in source's ASNs.
        filter = {'$match': {'ASNumber': {'$in': asns}}}
        aggregation_pipeline = [project, filter]
        ip_objects = IP.objects.aggregate(*aggregation_pipeline, useCursor=False)

        for ip_obj in ip_objects:
            add_source_to_ip(ip_obj, source_name)
        return True
    except Exception as e:
        return False

def add_source_to_ip(ip_object, source_name):
    """
    Adds a new source to the IP object's list of sources, if it is not already there.
    :param ip_object:
    :param source_name:
    :return:
    """
    if not source_name:
        return
    for src in ip_object.source:
        if src.name == source_name:
            # Source already in IP's sources
            return
    analyst = 'analysis_autofill'
    source = create_embedded_source(source_name, analyst=analyst)
    if source:
        ip_object.add_source(source)
        # Add a brand new releasability, and add an instance to that releasability.
        add_releasability('IP', ip_object.id, source.name, analyst)
        add_releasability_instance('IP', ip_object.id, source.name, analyst)
        ip_object.save()
    return