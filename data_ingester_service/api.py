import json
from jsonschema import validate, FormatChecker, ValidationError
from tastypie import authorization
from tastypie.authentication import MultiAuthentication
from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.user_tools import get_user_organization, user_sources
from handlers import save_ingest_data, aggregate_event_data
from vocabulary import IngestFields


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
        except Exception as e:
            response['message'] = "Error during schema validation: " + e.message
            self.crits_response(response, status=500)
        source = bundle.data.get('ProviderName')
        analyst = bundle.request.user.username
        if source not in user_sources(analyst):
            response['message'] = "Error: User not allowed to publish to source '" + str(source) + "'."
            self.crits_response(response, status=403)
        try:
            ingest_data_entries = bundle.data.get('ingestData', None)
            save_ingest_data(analyst, source, ingest_data_entries)
        except Exception as e:
            response['message'] = 'Error saving IP data: ' + e.message
            self.crits_response(response, status=500)
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
        actual_request = request
        if actual_request is None:
            # Request is likely contained in kwargs, not in request parameter.
            actual_request = kwargs['bundle'].request
        username = actual_request.GET.get('username', '')
        limit = actual_request.GET.get('limit', self.Meta.limit)
        if not isinstance(limit, int):
            try:
                limit = int(limit)
            except (TypeError, ValueError):
                response = {
                    'message': "'limit' parameter not an integer value.",
                    'return_code': 1
                }
                self.crits_response(response)
        if limit < 0:
            response = {
                'message': "'limit' parameter must be non-negative integer.",
                'return_code': 1
            }
            self.crits_response(response)
        # Limit of 0 in tastypie API returns unlimited number of results, so let aggregation return unlimited results.
        if limit == 0:
            limit = None
        result = aggregate_event_data(username, limit)
        objects = list(result)
        return objects

    def dehydrate(self, bundle):
        """
        Move bundle data to correct attribute, and convert number fields from strings to integers or floats.
        :param bundle:
        :return:
        """
        bundle.data = bundle.obj
        # Convert appropriate fields of Events to integers.
        for field_name in bundle.data:
            try:
                variable_type = IngestFields.api_field_to_variable_type(field_name)
                if variable_type == 'int':
                    bundle.data[field_name] = int(bundle.data[field_name])
            except (TypeError, ValueError):
                continue
        return bundle

    def alter_list_data_to_serialize(self, request, data):
        """
        Note: This function is called within get_list() of resources.py (tastypie library) after calling
        dehydrate() (the version defined in this class) on each bundle object.
        :param request:
        :param data:
        :return:
        """
        del data['meta']
        username = request.GET.get('username', '')
        # TODO: Consider whether a user would ever make two submissions with two different sources, one of which is not
        # their main organization.
        source_name = get_user_organization(username)
        data['ProviderName'] = source_name
        return data
