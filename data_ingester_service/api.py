from mongoengine import Document
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.crits_mongoengine import CritsDocument
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

        analyst = bundle.request.user.username
        source = bundle.data.get('source')
        ip_objects = bundle.data.get('new_entries', None)
        try:
            add_or_update_ip_object_group(analyst, source, ip_objects)
        except Exception, error:
            response = {
                'return_code': 1,
                'message': 'Error while saving data: ' + error.message
            }
            self.crits_response(response)

        response = {
            'return_code': 0,
            'message': 'All data has been saved!'
        }
        self.crits_response(response)