import pendulum
from pymongo import MongoClient
from crits.core.user_tools import user_sources
from crits.events.event import Event
from vocabulary import IngestFields


def save_ingest_data(analyst, source, ingest_data_entries):
    """
    Saves multiple IP objects to temporary database using the ingest data.

    :param analyst: The analyst who sent the POST message for the IP objects.
    :type analyst: str
    :param source: The source of the POST message for the IP objects.
    :type source: str
    :param ingest_data_entries: A list of objects with data about attacks from IP addresses.
    :type ingest_data_entries: list of dictionaries, each conforming to an 'ingestData' object in the definitions of the data ingester payload schema
    :return: (nothing)
    """
    client = MongoClient()
    staging_ips = client.staging_crits_data.ips
    for ingest_data_entry in ingest_data_entries:
        ingest_data_entry['analyst'] = analyst
        ingest_data_entry['source'] = source
        ingest_data_entry['timeReceived'] = pendulum.now('UTC')
        staging_ips.insert_one(ingest_data_entry)
    return


def aggregate_event_data(username=None, limit=None):
    """
    Aggregate data for all Events. If username is specified, only return results submitted by that user. If limit is
    specified, that value specifies the maximum number of results to return.
    :param username: The username of the user whose submissions we want to limit to.
    :type username: str
    :param limit: The maximum number of results to return.
    :type limit: int
    :return: pymongo.Cursor
    """
    aggregation_pipeline = []
    if limit is not None and not isinstance(limit, int):
        raise TypeError("'limit' must be an integer.")
    if username is not None:
        if not isinstance(username, basestring):
            raise TypeError("'username' must be a string.")
        sources = user_sources(username)
        match_user_source_stage = {'$match': {'source.name': {'$in': sources}}}
        aggregation_pipeline.append(match_user_source_stage)
    sort_stage = {'$sort': {'created': -1}}
    # NOTE: The two fields we unwind should only produce one document each, because each Event is associated with
    # exactly one IP.
    unwind_relationships_stage = {'$unwind': '$relationships'}
    IP_FIELD = 'ip_object'
    lookup_ips_stage = {
        '$lookup': {
            'from': 'ips',
            'localField': 'relationships.value',
            'foreignField': '_id',
            'as': IP_FIELD
        }
    }
    unwind_ip_field_stage = {'$unwind': '$' + IP_FIELD}
    project_event_object_fields_stage = {
        '$project': {
            '_id': 0,
            IngestFields.IP_ADDRESS: '$' + IP_FIELD + '.ip'
        }
    }
    for field_name in IngestFields.api_field_names():
        try:
            object_type = IngestFields.to_object_type(field_name)
            variable_type = IngestFields.api_field_to_variable_type(field_name)
        except ValueError:
            continue
        if variable_type == 'array':
            project_event_object_fields_stage['$project'][field_name] = {
                '$map': {
                    'input': {
                        '$filter': {
                            'input': '$objects',
                            'as': 'obj',
                            'cond': {'$eq': ['$$obj.type', object_type]}
                        }
                    },
                    'as': 'reporter_obj',
                    'in': '$$reporter_obj.value'
                }
            }
        else:
            project_event_object_fields_stage['$project'][field_name] = {
                '$let': {
                    'vars': {
                        'one_obj': {
                            '$arrayElemAt': [
                                {
                                    '$filter': {
                                        'input': '$objects',
                                        'as': 'obj',
                                        'cond': {'$eq': ['$$obj.type', object_type]}
                                    }
                                },
                                0
                            ]
                        }
                    },
                    'in': '$$one_obj.value'
                }
            }
    aggregation_pipeline.extend([
        sort_stage,
        unwind_relationships_stage,
        lookup_ips_stage,
        unwind_ip_field_stage,
        project_event_object_fields_stage
    ])
    if limit is not None:
        limit_stage = {'$limit': limit}
        aggregation_pipeline.append(limit_stage)
    collation = {
        'locale': 'en_US_POSIX',
        'numericOrdering': True
    }
    result = Event.objects.aggregate(*aggregation_pipeline, allowDiskUse=True, collation=collation, useCursor=False)
    return result
