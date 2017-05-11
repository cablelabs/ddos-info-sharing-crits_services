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

        analyst = bundle.request.user.username
        try:
            source = bundle.data.get('ProviderName')
        except Exception:
            response['message'] = "Error occurred while getting 'ProviderName' field."
            self.crits_response(response, status=500)
            return
        if source is None:
            response['message'] = "Error: 'ProviderName' field missing from input."
            self.crits_response(response, status=400)
            return

        try:
            sources = user_sources(analyst)
        except Exception:
            response['message'] = "Error occurred while getting user's sources."
            self.crits_response(response, status=500)
            return
        if source not in sources:
            response['message'] = "Error: User not allowed to publish to source '" + str(source) + "'."
            self.crits_response(response, status=403)
            return

        try:
            ip_objects = bundle.data.get('dis-data', None)
        except Exception:
            response['message'] = "Error occurred while getting 'dis-data' field."
            self.crits_response(response, status=500)
            return
        if ip_objects is None:
            response['message'] = "Error: 'dis-data' field missing from input."
            self.crits_response(response, status=400)
            return

        try:
            add_or_update_ip_object_group(analyst, source, ip_objects)
        except Exception as error:
            response['message'] = 'Error while saving IP data: ' + error.message
            self.crits_response(response, status=500)
            return

        response['message'] = 'All data has been saved!'
        response['return_code'] = 0
        self.crits_response(response)