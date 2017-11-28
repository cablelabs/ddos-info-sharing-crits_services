from datetime import datetime
from django.utils.dateparse import parse_datetime
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.user_tools import get_user_organization, user_sources
from crits.ips.ip import IP

from vocabulary import IPOutputFields, EventOutputFields


class DataDistributionResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.

    Currently supports GET.
    """
    def __init__(self):
        super(DataDistributionResource, self).__init__()
        self.request = None
        self.aggregation_pipeline = []

    class Meta:
        allowed_methods = ('get',)
        resource_name = "data_distribution_resource"
        collection_name = "outputData"
        excludes = ["id", "resource_uri", "unsupported_attrs"]
        limit = 20
        max_limit = 0
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

    # TODO: add support for searching on particular fields like FirstSeen, LastSeen, etc.
    def obj_get_list(self, request=None, **kwargs):
        """
        Returns the list of data to be sent in the 'outputData' field of a GET request.
        The following parameters are optional in the request:
        "limit", "sortBy", "sortOrder", "modifiedSince"

        :param request:
        :param kwargs:
        :return: list of objects
        """
        if request:
            self.request = request
        else:
            self.request = kwargs['bundle'].request
        self.aggregation_pipeline = []
        self._add_aggregation_stages()
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        result = IP.objects.aggregate(*self.aggregation_pipeline, allowDiskUse=True, collation=collation, useCursor=False)
        objects = list(result)
        return objects

    def _add_aggregation_stages(self):
        """
        Add all important stages to the aggregation pipeline.
        :return: (nothing)
        """
        username = self.request.GET.get('username', '')
        source_list = user_sources(username)
        match_releasability_stage = {'$match': {'releasability.name': {'$in': source_list}}}
        reported_by_sub_object_type = IPOutputFields.get_object_type_from_field_name(IPOutputFields.REPORTED_BY)
        project_ip_object_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$ip',
                'relationships': 1,
                IPOutputFields.REPORTED_BY: {
                    '$map': {
                        'input': {
                            '$filter': {
                                'input': '$objects',
                                'as': 'obj',
                                'cond': {'$eq': ['$$obj.type', reported_by_sub_object_type]}
                            }
                        },
                        'as': 'reporter_obj',
                        'in': '$$reporter_obj.value'
                    }
                }
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            if ip_output_field != IPOutputFields.REPORTED_BY:
                sub_object_type = IPOutputFields.get_object_type_from_field_name(ip_output_field)
                project_ip_object_fields_stage['$project'][ip_output_field] = {
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
        self.aggregation_pipeline = [
            match_releasability_stage,
            project_ip_object_fields_stage
        ]
        modified_since = self.request.GET.get('modifiedSince', '')
        if modified_since:
            try:
                modified_since_datetime = datetime.strptime(modified_since, "%Y-%m-%d")
            except ValueError:
                modified_since_datetime = parse_datetime(modified_since)
                if modified_since_datetime is None:
                    raise ValueError("'modifiedSince' not a properly formatted datetime string. Format must be RFC 3339 compliant or 'YYYY-MM-DD'.")
            match_ip_received_stage = {'$match': {IPOutputFields.LAST_TIME_RECEIVED: {'$gte': modified_since}}}
            self.aggregation_pipeline.append(match_ip_received_stage)
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
        middle_stages = [
            unwind_relationships_stage,
            lookup_events_stage,
            unwind_event_stage
        ]
        self.aggregation_pipeline.extend(middle_stages)
        if modified_since:
            match_event_created_stage = {'$match': {'event.created': {'$gte': modified_since_datetime}}}
            self.aggregation_pipeline.append(match_event_created_stage)
        attack_type_sub_object_type = EventOutputFields.get_object_type_from_field_name(EventOutputFields.ATTACK_TYPES)
        project_event_object_fields_stage = {
            '$project': {
                IPOutputFields.IP_ADDRESS: 1,
                EVENT_FIELD: {
                    EventOutputFields.TIME_RECORDED: '$'+EVENT_FIELD+'.created',
                    EventOutputFields.ATTACK_TYPES: {
                        '$map': {
                            'input': {
                                '$filter': {
                                    'input': '$'+EVENT_FIELD+'.objects',
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
        }
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                sub_object_type = EventOutputFields.get_object_type_from_field_name(event_output_field)
                project_event_object_fields_stage['$project'][EVENT_FIELD][event_output_field] = {
                    '$let': {
                        'vars': {
                            'one_obj': {
                                '$arrayElemAt': [
                                    {
                                        '$filter': {
                                            'input': '$' + EVENT_FIELD + '.objects',
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
        group_by_ip_stage = {
            '$group': {
                '_id': '$' + IPOutputFields.IP_ADDRESS,
                IPOutputFields.EVENTS: {'$push': '$event'}
            }
        }
        project_ip_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$_id',
                IPOutputFields.EVENTS: 1
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            project_event_object_fields_stage['$project'][ip_output_field] = 1
            group_by_ip_stage['$group'][ip_output_field] = {'$first': '$' + ip_output_field}
            project_ip_fields_stage['$project'][ip_output_field] = 1
        final_stages = [
            project_event_object_fields_stage,
            group_by_ip_stage,
            project_ip_fields_stage
        ]
        self.aggregation_pipeline.extend(final_stages)
        sort_by = self.request.GET.get('sortBy', '')
        if sort_by:
            if sort_by not in IPOutputFields.ALL_FIELDS or sort_by == IPOutputFields.EVENTS:
                raise ValueError("'sortBy' parameter '" + sort_by + "' is not a valid field to sort on.")
            # Default to descending order
            sort_order = self.request.GET.get('sortOrder', 'desc')
            sort_order_number = -1 if (sort_order == 'desc') else 1
            sort_stage = {'$sort': {sort_by: sort_order_number}}
            self.aggregation_pipeline.append(sort_stage)
        limit = self.request.GET.get('limit', '20')
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            raise ValueError("'limit' parameter not an integer value.")
        limit_stage = {'$limit': limit}
        self.aggregation_pipeline.append(limit_stage)

    def dehydrate(self, bundle):
        """
        Restructure fields in bundle so data is passed on correctly, remove fields that are null or are not something we
        intended on returning, and convert number fields from strings to integers or floats (depending on the field).

        :param bundle:
        :return:
        """
        bundle.data = bundle.obj
        # Remove all top-level null fields from IP object.
        fields_to_remove = []
        for field_name in bundle.data:
            if not bundle.data[field_name]:
                fields_to_remove.append(field_name)
        for field in fields_to_remove:
            del bundle.data[field]
        # Convert appropriate fields of IP object to integers.
        for field_name in IPOutputFields.INTEGER_FIELDS:
            if bundle.data.get(field_name):
                try:
                    bundle.data[field_name] = int(bundle.data[field_name])
                except (TypeError, ValueError):
                    pass
        # Convert appropriate fields of IP object to floating point numbers.
        for field_name in IPOutputFields.FLOAT_FIELDS:
            if bundle.data.get(field_name):
                try:
                    bundle.data[field_name] = float(bundle.data[field_name])
                except (TypeError, ValueError):
                    pass
        if bundle.data.get(IPOutputFields.EVENTS):
            # Dehydrate each event.
            for i in range(0, len(bundle.data[IPOutputFields.EVENTS])):
                # Add "Z" to the end of the timestamp so we know it's in UTC.
                time_recorded = bundle.data[IPOutputFields.EVENTS][i][EventOutputFields.TIME_RECORDED]
                bundle.data[IPOutputFields.EVENTS][i][EventOutputFields.TIME_RECORDED] = time_recorded.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                # Remove all null fields from event.
                fields_to_remove = []
                for field_name in bundle.data[IPOutputFields.EVENTS][i]:
                    if not bundle.data[IPOutputFields.EVENTS][i][field_name]:
                        fields_to_remove.append(field_name)
                for field in fields_to_remove:
                    del bundle.data[IPOutputFields.EVENTS][i][field]
                # Convert appropriate fields of event to integers.
                for integer_field in EventOutputFields.INTEGER_FIELDS:
                    if bundle.data[IPOutputFields.EVENTS][i].get(integer_field):
                        try:
                            bundle.data[IPOutputFields.EVENTS][i][integer_field] = int(bundle.data[IPOutputFields.EVENTS][i][integer_field])
                        except (TypeError, ValueError):
                            pass
        return bundle

    def alter_list_data_to_serialize(self, request, data):
        """
        Note: This function gets called after calling dehydrate() (above) on each bundle object, all within get_list()
        of resources.py of the tastypie library.

        :param request:
        :param data:
        :return:
        """
        del data['meta']
        username = request.GET.get('username', '')
        source_name = get_user_organization(username)
        data['SourceName'] = source_name
        return data
