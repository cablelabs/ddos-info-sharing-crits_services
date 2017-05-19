import json
from jsonschema import validate, FormatChecker, ValidationError
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.user_tools import user_sources

from handlers import add_or_update_ip_object_group


class DataIngesterResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.
    """

    def __init__(self):
        super(DataIngesterResource, self).__init__()
        schema_file = open('/home/infosharing/git/crits_services/data_ingester_service/Data Ingester Payload Schema.json', 'r')
        self.input_schema = json.load(schema_file)

    class Meta:
        allowed_methods = ('post')
        resource_name = "data_ingester_resource"
        collection_name = "dis-data"
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

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
            'message': "Error!",
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

        try:
            source = bundle.data.get('ProviderName')
        except Exception as e:
            response['message'] = "Error getting 'ProviderName': " + e.message
            self.crits_response(response, status=500)
            return
        try:
            analyst = bundle.request.user.username
            sources = user_sources(analyst)
        except Exception as e:
            response['message'] = "Error getting user's sources: " + e.message
            self.crits_response(response, status=500)
            return
        if source not in sources:
            response['message'] = "Error: User not allowed to publish to source '" + str(source) + "'."
            self.crits_response(response, status=403)
            return
        try:
            ip_objects = bundle.data.get('dis-data', None)
        except Exception as e:
            response['message'] = "Error getting 'dis-data': " + e.message
            self.crits_response(response, status=500)
            return
        try:
            add_or_update_ip_object_group(analyst, source, ip_objects)
        except Exception as e:
            response['message'] = 'Error saving IP data: ' + e.message
            self.crits_response(response, status=500)
            return

        response['message'] = 'All data has been saved!'
        response['return_code'] = 0
        self.crits_response(response)
