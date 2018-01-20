import json
import pendulum
from pymongo import MongoClient
from jsonschema import validate, FormatChecker, ValidationError
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.user_tools import get_user_organization, user_sources
from crits.events.event import Event

from vocabulary import IPOutputFields, EventOutputFields


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
    # TODO: check return type
    aggregation_pipeline = []
    if username is not None:
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
    attack_type_sub_object_type = EventOutputFields.get_object_type_from_field_name(EventOutputFields.ATTACK_TYPES)
    project_event_object_fields_stage = {
        '$project': {
            '_id': 0,
            IPOutputFields.IP_ADDRESS: '$' + IP_FIELD + '.ip',
            EventOutputFields.ATTACK_TYPES: {
                '$map': {
                    'input': {
                        '$filter': {
                            'input': '$objects',
                            'as': 'obj',
                            'cond': {'$eq': ['$$obj.type', attack_type_sub_object_type]}
                        }
                    },
                    'as': 'reporter_obj',
                    'in': '$$reporter_obj.value'
                }
            }
        }
    }
    for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
        if event_output_field != EventOutputFields.ATTACK_TYPES:
            sub_object_type = EventOutputFields.get_object_type_from_field_name(event_output_field)
            project_event_object_fields_stage['$project'][event_output_field] = {
                '$let': {
                    'vars': {
                        'one_obj': {
                            '$arrayElemAt': [
                                {
                                    '$filter': {
                                        'input': '$objects',
                                        'as': 'obj',
                                        'cond': {'$eq': ['$$obj.type', sub_object_type]}
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
        project_event_object_fields_stage,
    ])
    if limit is not None:
        limit_stage = {'$limit': limit}
        aggregation_pipeline.append(limit_stage)
