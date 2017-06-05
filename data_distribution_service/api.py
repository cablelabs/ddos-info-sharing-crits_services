from datetime import datetime
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.user_tools import get_user_organization, user_sources
from crits.ips.ip import IP
from crits.vocabulary.objects import ObjectTypes

from DataDistributionObject import DataDistributionObject
from handlers import create_raw_query, get_limit
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
        object_class = DataDistributionObject
        allowed_methods = ('get')
        resource_name = "data_distribution_resource"
        collection_name = "outputData"
        excludes = ["resource_uri"] #["id", "resource_uri", "unsupported_attrs"]
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

    def alter_list_data_to_serialize(self, request, data):
        del data['meta']
        username = request.GET.get('username', '')
        source_name = get_user_organization(username)
        data['SourceName'] = source_name
        return data

    def dehydrate(self, bundle):
        """
        Restructure fields in bundle so data is passed on correctly, remove fields that are null or are not something we
        intended on returning, and convert number fields from strings to integers or floats (depending on the field).
        
        :param bundle: 
        :return: 
        """
        bundle.data = bundle.obj
        fields_to_remove = []
        all_output_fields = IPOutputFields.ALL_FIELDS[:]
        for field_name in bundle.data:
            if not (bundle.data[field_name] and field_name in all_output_fields):
                fields_to_remove.append(field_name)
            elif field_name in IPOutputFields.INTEGER_FIELDS:
                try:
                    bundle.data[field_name] = int(bundle.data[field_name])
                except (TypeError, ValueError):
                    continue
            elif field_name in IPOutputFields.FLOAT_FIELDS:
                try:
                    bundle.data[field_name] = float(bundle.data[field_name])
                except (TypeError, ValueError):
                    continue
            elif field_name == IPOutputFields.EVENTS:
                # For each event, change number fields to number values
                for i in range(0, len(bundle.data[field_name])):
                    try:
                        bundle.data[field_name][i][EventOutputFields.TOTAL_BYTES_SENT] = int(bundle.data[field_name][i][EventOutputFields.TOTAL_BYTES_SENT])
                    except (TypeError, ValueError):
                        continue
                    try:
                        bundle.data[field_name][i][EventOutputFields.TOTAL_PACKETS_SENT] = int(bundle.data[field_name][i][EventOutputFields.TOTAL_PACKETS_SENT])
                    except (TypeError, ValueError):
                        continue
                    try:
                        bundle.data[field_name][i][EventOutputFields.PEAK_BYTES_PER_SECOND] = int(bundle.data[field_name][i][EventOutputFields.PEAK_BYTES_PER_SECOND])
                    except (TypeError, ValueError):
                        continue
                    try:
                        bundle.data[field_name][i][EventOutputFields.PEAK_PACKETS_PER_SECOND] = int(bundle.data[field_name][i][EventOutputFields.PEAK_PACKETS_PER_SECOND])
                    except (TypeError, ValueError):
                        continue
                    try:
                        bundle.data[field_name][i][EventOutputFields.SOURCE_PORT] = int(bundle.data[field_name][i][EventOutputFields.SOURCE_PORT])
                    except (TypeError, ValueError):
                        continue
                    try:
                        bundle.data[field_name][i][EventOutputFields.DESTINATION_PORT] = int(bundle.data[field_name][i][EventOutputFields.DESTINATION_PORT])
                    except (TypeError, ValueError):
                        continue
        for field in fields_to_remove:
            del bundle.data[field]
        return bundle

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
        result = IP.objects.aggregate(*self.aggregation_pipeline, collation=collation, useCursor=False)
        objects = list(result)
        return objects

    def _add_aggregation_stages(self):
        """
        Add all important stages to the aggregation pipeline.
        :return: (nothing)
        """
        self._match_ips_on_releasability()
        self._project_ip_sub_object_fields()
        #self._unwind_and_match_on_reporting_sources()
        #self._group_documents_by_ip()
        self._lookup_related_events()
        self._match_modified_since_parameter()
        self._project_event_fields_to_top_level()
        self._group_documents_by_event_id()
        self._project_event_fields_to_nested_level()
        self._group_documents_by_ip_with_event_data()
        self._project_ip_address()
        self._add_sort_to_pipeline()
        self._add_limit_to_pipeline()

    def _match_ips_on_releasability(self):
        """
        Filter on IP objects so the output includes only IPs that contain a releasability associated with one of the
        user's sources.
        :return: (nothing)
        """
        username = self.request.GET.get('username', '')
        source_list = user_sources(username)
        match_stage = {'$match': {'releasability.name': {'$in': source_list}}}
        self.aggregation_pipeline.append(match_stage)

    # TODO: compare performance of using $unwind with performance of the complicated thing I did with $let
    def _project_ip_sub_object_fields(self):
        """
        Adds an aggregation stage that projects the values of each IP's sub-objects to top-level fields.
        :return: (nothing)
        """
        project_stage = {
            '$project': {
                '_id': 0,
                'ip': 1,
                'relationships': 1
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            sub_object_type = IPOutputFields.get_object_type_from_field_name(ip_output_field)
            project_stage['$project'][ip_output_field] = {
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
        self.aggregation_pipeline.append(project_stage)

    def _lookup_related_events(self):
        """
        Adds stages that copy events from Events collection that are related to the given IPs.
        :return: (nothing)
        """
        unwind_relationships_stage = {'$unwind': '$relationships'}
        lookup_stage = {
            '$lookup': {
                'from': 'events',
                'localField': 'relationships.value',
                'foreignField': '_id',
                'as': 'event'
            }
        }
        unwind_event_stage = {'$unwind': '$event'}
        # NOTE: Even though we unwind 'event', we expect that there will only be one new document per each existing
        # document because of how events are tied to IPs, and we already unwinded the relationships field.
        stages = [unwind_relationships_stage, lookup_stage, unwind_event_stage]
        self.aggregation_pipeline.extend(stages)

    def _match_modified_since_parameter(self):
        """
        Adds a filter on events that occurred since the input 'modifiedSince' time.
        :return: 
        """
        modified_since = self.request.GET.get('modifiedSince', '')
        if modified_since:
            try:
                modified_since_datetime = datetime.strptime(modified_since, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                try:
                    modified_since_datetime = datetime.strptime(modified_since, "%Y-%m-%d")
                except ValueError:
                    raise ValueError("'modifiedSince' time not a properly formatted ISO string.")
            # TODO: confirm that this query is correct
            match = {'$match': {'event.created': {'$gte': modified_since_datetime}}}
            self.aggregation_pipeline.append(match)

    def _project_event_fields_to_top_level(self):
        """
        Adds stages that temporarily move fields nested in sub-objects of events to top-level fields of the documents.
        :return: (nothing)
        """
        unwind_stage = {'$unwind': '$event.objects'}
        project_stage = {
            '$project': {
                'eventID': '$event._id',
                'eventtimeRecorded': {
                    '$dateToString': {
                        'format': '%Y-%m-%dT%H:%M:%S.%LZ',
                        'date': '$event.created'
                    }
                }
            }
        }
        for ip_output_field in IPOutputFields.NON_AGGREGATE_FIELDS:
            project_stage['$project'][ip_output_field] = 1
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            sub_object_type = EventOutputFields.get_object_type_from_field_name(event_output_field)
            project_stage['$project']['event' + event_output_field] = {
                '$cond': {
                    'if': {'$eq': ['$event.objects.type', sub_object_type]},
                    'then': '$event.objects.value',
                    'else': None
                }
            }
        stages = [unwind_stage, project_stage]
        self.aggregation_pipeline.extend(stages)

    def _group_documents_by_event_id(self):
        """
        Adds a stage that groups repeated documents together by the Event ID.
        :return: (nothing)
        """
        group_stage = {
            '$group': {
                '_id': '$eventID',
                IPOutputFields.IP_ADDRESS: {'$first': '$_id'},
                'eventtimeRecorded': {'$first': '$eventtimeRecorded'},
                'eventattackTypes': {'$addToSet': '$eventattackTypes'}
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            group_stage['$group'][ip_output_field] = {'$first': '$' + ip_output_field}
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                group_stage['$group']['event' + event_output_field] = {'$max': '$event' + event_output_field}
        self.aggregation_pipeline.append(group_stage)

    def _project_event_fields_to_nested_level(self):
        """
        Adds a stage that moves event fields into a single field named 'event'.
        :return: (nothing)
        """
        project_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: 1,
                'event': {
                    'timeRecorded': '$eventtimeRecorded',
                    'attackTypes': {
                        '$filter': {
                            'input': '$eventattackTypes',
                            'as': 'attackType',
                            'cond': {'$ne': ['$$attackType', None]}
                        }
                    }
                },
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            project_stage['$project'][ip_output_field] = 1
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                project_stage['$project']['event'][event_output_field] = '$event' + event_output_field
        self.aggregation_pipeline.append(project_stage)

    def _group_documents_by_ip_with_event_data(self):
        """
        Adds an aggregation stage that groups repeated documents together by the IP address, except that unlike the last
        time we grouped by IP, this stage adds new fields based on the events associated with the IP.
        :return: (nothing)
        """
        group_stage = {
            '$group': {
                '_id': '$' + IPOutputFields.IP_ADDRESS,
                #IPOutputFields.LAST_TIME_RECEIVED: {'$max': '$event.' + EventOutputFields.TIME_RECORDED},
                #IPOutputFields.TOTAL_BYTES_SENT: {'$sum': '$event.' + EventOutputFields.TOTAL_BYTES_SENT},
                #IPOutputFields.TOTAL_PACKETS_SENT: {'$sum': '$event.' + EventOutputFields.TOTAL_PACKETS_SENT},
                IPOutputFields.EVENTS: {'$push': '$event'}
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            group_stage['$group'][ip_output_field] = {'$first': '$' + ip_output_field}
        self.aggregation_pipeline.append(group_stage)

    def _project_ip_address(self):
        """
        Adds an aggregation stage that simply remaps the "_id" field to the IP address field.
        :return: (nothing)
        """
        project_ip_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$_id'
            }
        }
        for ip_output_field in IPOutputFields.ALL_FIELDS:
            if ip_output_field != IPOutputFields.IP_ADDRESS:
                project_ip_fields_stage['$project'][ip_output_field] = 1
        self.aggregation_pipeline.append(project_ip_fields_stage)

    def _add_sort_to_pipeline(self):
        """
        Defines the way to sort the IP addresses, and adds it to the aggregation pipeline.
        :return: (nothing)
        """
        sort_by = self.request.GET.get('sortBy', '')
        if sort_by:
            if sort_by not in IPOutputFields.ALL_FIELDS or sort_by == IPOutputFields.EVENTS:
                raise ValueError("'sortBy' parameter '" + sort_by + "' is not a valid field to sort on.")
            # Default to descending order
            sort_order = self.request.GET.get('sortOrder', 'desc')
            sort_order_number = -1 if (sort_order == 'desc') else 1
            sort_stage = {'$sort': {sort_by: sort_order_number}}
            self.aggregation_pipeline.append(sort_stage)

    def _add_limit_to_pipeline(self):
        """
        Defines the limit on the number of IP addresses to return, and adds it to the aggregation pipeline.
        :return: (nothing)
        """
        input_limit = self.request.GET.get('limit', '20')
        try:
            limit_integer = int(input_limit)
        except (TypeError, ValueError):
            raise ValueError("'limit' field set to invalid value. Must be integer.")
        limit = {'$limit': limit_integer}
        self.aggregation_pipeline.append(limit)
