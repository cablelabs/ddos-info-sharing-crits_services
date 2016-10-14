from mongoengine import Document
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.crits_mongoengine import CritsDocument
from crits.core.user_tools import user_sources
from handlers import add_or_update_ip_object_group


class DataIngesterObject(CritsDocument, Document):
    """
    Class to store data if necessary in future work.
    """

class DataIngesterResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.

    Currently supports POST.
    """

    class Meta:
        object_class = DataIngesterObject
        allowed_methods = ('post')
        resource_name = "data_ingester_resource"
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
            'return_code': 1,
            'message': "Error!"
        }

        analyst = bundle.request.user.username
        try:
            source = bundle.data.get('ProviderName')
        except Exception:
            response['message'] = "Error: 'ProviderName' missing."
            self.crits_response(response)
            return

        try:
            sources = user_sources(analyst)
        except Exception:
            response['message'] = "Error: Problem getting user sources."
            self.crits_response(response)
            return

        if source not in sources:
            response['message'] = "Error: User not allowed to publish to source '" + str(source) + "'."
            self.crits_response(response)
            return

        try:
            ip_objects = bundle.data.get('dis-data', None)
        except Exception:
            response['message'] = "Error: 'dis-data' missing."
            self.crits_response(response)
            return

        if ip_objects is None:
            response['message'] = "Error: 'dis-data' missing."
            self.crits_response(response)
            return

        try:
            add_or_update_ip_object_group(analyst, source, ip_objects)
        except Exception, error:
            response['message'] = 'Error while saving IP data: ' + error.message + '.'
            self.crits_response(response)
            return

        response['return_code'] = 1
        response['message'] = 'All data has been saved!'
        self.crits_response(response)