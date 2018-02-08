import pendulum
import strict_rfc3339
from crits.core.user_tools import user_sources
from crits.ips.ip import IP
from vocabulary import DistributionFields


def collect_ip_data(username=None, limit=None, modified_since=None,
                    sort_by=None, sort_descending=True, min_number_of_reporters=1):
    # Check parameters before setting up aggregation query.
    if username is not None and not isinstance(username, basestring):
        raise TypeError("'username' must be a string.")
    if limit is not None and not isinstance(limit, int):
        raise TypeError("'limit' must be an integer.")
    modified_since_datetime = None
    if modified_since is not None:
        if not isinstance(modified_since, basestring):
            raise TypeError("'modified_since' must be a string.")
        if strict_rfc3339.validate_rfc3339(modified_since):
            modified_since_datetime = pendulum.parse(modified_since)
        else:
            try:
                modified_since_datetime = pendulum.strptime(modified_since, "%Y-%m-%d")
            except ValueError:
                raise ValueError("'modifiedSince' not a properly formatted datetime string. Format must be RFC 3339 compliant or 'YYYY-MM-DD'.")
    if sort_by is not None:
        if not isinstance(sort_by, basestring):
            raise TypeError("'sort_by' must be a string.")
        if sort_by not in DistributionFields.ip_field_names() or sort_by == DistributionFields.EVENTS:
            raise ValueError("'sort_by' parameter '" + sort_by + "' is not a valid field to sort on.")
    if not isinstance(sort_descending, bool):
        raise TypeError("'sort_descending' must be a bool.")
    if not isinstance(min_number_of_reporters, int):
        raise TypeError("'min_number_of_reporters' must be an integer.")
    aggregation_pipeline = []
    if username is not None:
        sources = user_sources(username)
        match_releasability_stage = {'$match': {'releasability.name': {'$in': sources}}}
        aggregation_pipeline.append(match_releasability_stage)
    project_ip_object_fields_stage = {
        '$project': {
            '_id': 0,
            DistributionFields.IP_ADDRESS: '$ip',
            'relationships': 1
        }
    }
    for ip_field_name in DistributionFields.ip_field_names():
        try:
            object_type = DistributionFields.to_object_type(ip_field_name)
            variable_type = DistributionFields.api_field_to_variable_type(ip_field_name)
        except ValueError:
            continue
        if variable_type == 'array':
            project_ip_object_fields_stage['$project'][ip_field_name] = {
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
            project_ip_object_fields_stage['$project'][ip_field_name] = {
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
    aggregation_pipeline.append(project_ip_object_fields_stage)
    if modified_since is not None:
        # TODO: Confirm that string comparison is acceptable. Otherwise, manually filter after aggregation.
        match_ip_received_stage = {'$match': {DistributionFields.LAST_TIME_RECEIVED: {'$gte': modified_since}}}
        aggregation_pipeline.append(match_ip_received_stage)
    match_min_number_of_reporters_stage = {'$match': {DistributionFields.NUMBER_OF_REPORTERS: {'$gte': str(min_number_of_reporters)}}}
    unwind_relationships_stage = {'$unwind': '$relationships'}
    EVENT_FIELD = 'event'
    lookup_events_stage = {
        '$lookup': {
            'from': 'events',
            'localField': 'relationships.value',
            'foreignField': '_id',
            'as': EVENT_FIELD
        }
    }
    # NOTE: Unwinding the 'event' field should produce only one document because each relationship references one
    # specific object by its ID field.
    unwind_event_stage = {'$unwind': '$' + EVENT_FIELD}
    aggregation_pipeline.extend([
        match_min_number_of_reporters_stage,
        unwind_relationships_stage,
        lookup_events_stage,
        unwind_event_stage
    ])
    if modified_since is not None and modified_since_datetime is not None:
        match_event_created_stage = {'$match': {'event.created': {'$gte': modified_since_datetime}}}
        aggregation_pipeline.append(match_event_created_stage)
    project_event_object_fields_stage = {
        '$project': {
            DistributionFields.IP_ADDRESS: 1,
            EVENT_FIELD: {DistributionFields.TIME_RECORDED: '$' + EVENT_FIELD + '.created'}
        }
    }
    for event_field_name in DistributionFields.event_field_names():
        try:
            object_type = DistributionFields.to_object_type(event_field_name)
            variable_type = DistributionFields.api_field_to_variable_type(event_field_name)
        except ValueError:
            continue
        if variable_type == 'array':
            project_event_object_fields_stage['$project'][EVENT_FIELD][event_field_name] = {
                '$map': {
                    'input': {
                        '$filter': {
                            'input': '$' + EVENT_FIELD + '.objects',
                            'as': 'obj',
                            'cond': {'$eq': ['$$obj.type', object_type]}
                        }
                    },
                    'as': 'reporter_obj',
                    'in': '$$reporter_obj.value'
                }
            }
        else:
            project_event_object_fields_stage['$project'][EVENT_FIELD][event_field_name] = {
                '$let': {
                    'vars': {
                        'one_obj': {
                            '$arrayElemAt': [
                                {
                                    '$filter': {
                                        'input': '$' + EVENT_FIELD + '.objects',
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
    group_by_ip_stage = {
        '$group': {
            '_id': '$' + DistributionFields.IP_ADDRESS,
            DistributionFields.EVENTS: {'$push': '$event'}
        }
    }
    project_ip_fields_stage = {
        '$project': {
            '_id': 0,
            DistributionFields.IP_ADDRESS: '$_id',
            DistributionFields.EVENTS: 1
        }
    }
    for ip_output_field in DistributionFields.ip_field_names():
        if ip_output_field != DistributionFields.IP_ADDRESS and ip_output_field != DistributionFields.EVENTS:
            project_event_object_fields_stage['$project'][ip_output_field] = 1
            group_by_ip_stage['$group'][ip_output_field] = {'$first': '$' + ip_output_field}
            project_ip_fields_stage['$project'][ip_output_field] = 1
    aggregation_pipeline.extend([
        project_event_object_fields_stage,
        group_by_ip_stage,
        project_ip_fields_stage
    ])
    if sort_by is not None:
        sort_order_number = -1 if sort_descending else 1
        sort_stage = {'$sort': {sort_by: sort_order_number}}
        aggregation_pipeline.append(sort_stage)
    if limit is not None:
        limit_stage = {'$limit': limit}
        aggregation_pipeline.append(limit_stage)
    collation = {
        'locale': 'en_US_POSIX',
        'numericOrdering': True
    }
    result = IP.objects.aggregate(*aggregation_pipeline, allowDiskUse=True, collation=collation, useCursor=False)
    return result
