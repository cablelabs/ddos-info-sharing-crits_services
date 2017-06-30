import json
from jsonschema import validate, FormatChecker, ValidationError
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.user_tools import get_user_organization, user_sources
from crits.ips.ip import IP

from handlers import save_ingest_data
from vocabulary import IPOutputFields, EventOutputFields


class DataIngesterResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.
    """

    class Meta:
        allowed_methods = ('get', 'post')
        resource_name = "data_ingester_resource"
        collection_name = "ingestData"
        excludes = ["id", "resource_uri", "unsupported_attrs"]
        limit = 20
        max_limit = 0
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

    def __init__(self):
        super(DataIngesterResource, self).__init__()
        # ASSUMPTION: File named 'Data-Ingester-Payload-Schema.json' exists in directory '/data'.
        path_to_schema = '/data/Data-Ingester-Payload-Schema.json'
        schema_file = open(path_to_schema, 'r')
        self.input_schema = json.load(schema_file)

    def obj_create(self, bundle, **kwargs):
        """
        Handles POST request to add or update IP objects using format specified for MSOs.

        :param bundle: Bundle containing the information to create the Identifier.
                       Should contain a list of IP-like objects.
        :type bundle: Tastypie Bundle object.
        :param kwargs: (Not used.)
        :returns: (nothing.)
        """
        response = {
            'message': '',
            'return_code': 1
        }
        try:
            validate(bundle.data, self.input_schema, format_checker=FormatChecker())
        except ValidationError as e:
            response['message'] = "Validation Error: " + e.message
            self.crits_response(response, status=400)
            return
        except Exception as e:
            response['message'] = "Error during schema validation: " + e.message
            self.crits_response(response, status=500)
            return
        source = bundle.data.get('ProviderName')
        analyst = bundle.request.user.username
        sources = user_sources(analyst)
        if source not in sources:
            response['message'] = "Error: User not allowed to publish to source '" + str(source) + "'."
            self.crits_response(response, status=403)
            return
        try:
            ingest_data_entries = bundle.data.get('ingestData', None)
            save_ingest_data(analyst, source, ingest_data_entries)
        except Exception as e:
            response['message'] = 'Error saving IP data: ' + e.message
            self.crits_response(response, status=500)
            return
        response['message'] = 'All data has been saved!'
        response['return_code'] = 0
        self.crits_response(response)

    def obj_get_list(self, request=None, **kwargs):
        """
        Returns the list of data to be sent in the 'outputData' field of a GET request.

        :param request:
        :param kwargs:
        :return: list of objects
        """
        # PROBLEM: What if users submit their own IP? We distinguished submitter from owner using releasability, but what if submitter was the owner?
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
        self._match_ips_on_releasability()
        self._project_ip_sub_object_fields()
        self._lookup_related_events()
        self._project_event_fields_to_top_level()
        self._group_documents_by_event_id()
        self._project_event_fields_to_nested_level()
        self._group_documents_by_ip_with_event_data()
        self._project_ip_address()
        self._project_event_fields()
        self._add_sort_to_pipeline()

    def _match_ips_on_releasability(self):
        # Find all ips whose source includes user's organization in source, but not in relasability
        username = self.request.GET.get('username', '')
        user_organization = get_user_organization(username)
        match_stage = {
            '$match': {
                'source.name': user_organization,
                'releasability.name': {'$ne': user_organization}
            }
        }
        self.aggregation_pipeline.append(match_stage)

    def _project_ip_sub_object_fields(self):
        """
        Adds an aggregation stage that projects the values of each IP's sub-objects to top-level fields.
        :return: (nothing)
        """
        project_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$ip',
                'relationships': 1,
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

    def _project_event_fields_to_top_level(self):
        """
        Adds stages that temporarily move fields nested in sub-objects of events to top-level fields of the documents.
        :return: (nothing)
        """
        unwind_stage = {'$unwind': '$event.objects'}
        project_stage = {
            '$project': {
                IPOutputFields.IP_ADDRESS: 1,
                'eventID': '$event._id',
                'eventtimeRecorded': {
                    '$dateToString': {
                        'format': '%Y-%m-%dT%H:%M:%S.%LZ',
                        'date': '$event.created'
                    }
                }
            }
        }
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
                IPOutputFields.IP_ADDRESS: {'$first': '$'+IPOutputFields.IP_ADDRESS},
                'eventtimeRecorded': {'$first': '$eventtimeRecorded'},
                'eventattackTypes': {'$addToSet': '$eventattackTypes'}
            }
        }
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
                    EventOutputFields.TIME_RECORDED: '$eventtimeRecorded',
                    EventOutputFields.ATTACK_TYPES: {
                        '$filter': {
                            'input': '$eventattackTypes',
                            'as': 'attackType',
                            'cond': {'$ne': ['$$attackType', None]}
                        }
                    }
                },
            }
        }
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
                'maxTimeRecorded': {'$max': '$event.timeRecorded'},
                IPOutputFields.EVENTS: {'$push': '$event'}
            }
        }
        self.aggregation_pipeline.append(group_stage)

    def _project_ip_address(self):
        """
        Adds an aggregation stage that simply remaps the "_id" field to the IP address field.
        :return: (nothing)
        """
        project_ip_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$_id',
                IPOutputFields.EVENTS: {
                    '$filter': {
                        'input': '$events',
                        'as': 'event',
                        'cond': {'$eq': ['$$event.timeRecorded', '$maxTimeRecorded']}
                    }
                }
            }
        }
        self.aggregation_pipeline.append(project_ip_fields_stage)

    def _project_event_fields(self):
        unwind = {'$unwind': '$events'}
        project = {
            '$project': {
                IPOutputFields.IP_ADDRESS: 1
            }
        }
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            project['$project'][event_output_field] = '$events.' + event_output_field
        stages = [unwind, project]
        self.aggregation_pipeline.extend(stages)

    def _add_sort_to_pipeline(self):
        """
        Defines the way to sort the IP addresses, and adds it to the aggregation pipeline.
        :return: (nothing)
        """
        sort_stage = {'$sort': {IPOutputFields.LAST_TIME_RECEIVED: -1}}
        self.aggregation_pipeline.append(sort_stage)

    def dehydrate(self, bundle):
        """
        Restructure fields in bundle so data is passed on correctly, remove fields that are null or are not something we
        intended on returning, and convert number fields from strings to integers or floats (depending on the field).

        :param bundle:
        :return:
        """
        bundle.data = bundle.obj
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
        # Convert appropriate fields of event to integers.
        for integer_field in EventOutputFields.INTEGER_FIELDS:
            if bundle.data.get(integer_field):
                try:
                    bundle.data[integer_field] = int(bundle.data[integer_field])
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
        data['ProviderName'] = source_name
        return data
