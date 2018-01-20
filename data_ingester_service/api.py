import json
from jsonschema import validate, FormatChecker, ValidationError
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.user_tools import get_user_organization, user_sources
from crits.events.event import Event

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
        self.request = None
        self.aggregation_pipeline = []

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
        if source not in user_sources(analyst):
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
        if request:
            self.request = request
        else:
            self.request = kwargs['bundle'].request
        self._add_aggregation_stages()
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        result = Event.objects.aggregate(*self.aggregation_pipeline, allowDiskUse=True, collation=collation, useCursor=False)
        objects = list(result)
        return objects

    def _add_aggregation_stages(self):
        """
        Initialize all stages for a MongoDB aggregation query to get all events submitted by the requesting user.
        :return: (nothing)
        """
        username = self.request.GET.get('username', '')
        user_organization = get_user_organization(username)
        match_user_submissions_stage = {
            '$match': {
                'source.name': user_organization
            }
        }
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
        unwind_ip_field_stage = {'$unwind': '$'+IP_FIELD}
        attack_type_sub_object_type = EventOutputFields.get_object_type_from_field_name(EventOutputFields.ATTACK_TYPES)
        project_event_object_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$'+IP_FIELD+'.ip',
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
        limit = self.request.GET.get('limit', '20')
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            raise ValueError("'limit' parameter not an integer value.")
        limit_stage = {'$limit': limit}
        self.aggregation_pipeline = [
            match_user_submissions_stage,
            sort_stage,
            unwind_relationships_stage,
            lookup_ips_stage,
            unwind_ip_field_stage,
            project_event_object_fields_stage,
            limit_stage
        ]

    def dehydrate(self, bundle):
        """
        Move bundle data to correct attribute, and convert number fields from strings to integers or floats.

        :param bundle:
        :return:
        """
        bundle.data = bundle.obj
        # Convert appropriate fields of events to integers.
        for integer_field in EventOutputFields.INTEGER_FIELDS:
            if bundle.data.get(integer_field):
                try:
                    bundle.data[integer_field] = int(bundle.data[integer_field])
                except (TypeError, ValueError):
                    pass
        return bundle

    def alter_list_data_to_serialize(self, request, data):
        """
        Note: This function is called within get_list() of resources.py (tastypie library) after calling
        dehydrate() (defined in this class) on each bundle object.

        :param request:
        :param data:
        :return:
        """
        del data['meta']
        username = request.GET.get('username', '')
        source_name = get_user_organization(username)
        data['ProviderName'] = source_name
        return data
