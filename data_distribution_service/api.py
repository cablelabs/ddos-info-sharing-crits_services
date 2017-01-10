from mongoengine import Document, StringField, ListField, DynamicField, DictField
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.crits_mongoengine import CritsDocument
from crits.ips.ip import IP


class DataDistributionObject(CritsDocument, Document):
    """
    Class to store data for GET requests.
    """
    ip = StringField()


class DataDistributionResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.

    Currently supports GET.
    """

    class Meta:
        object_class = DataDistributionObject
        allowed_methods = ('get')
        resource_name = "data_distribution_resource"
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

    #def get_object_list(self, request):
    #    """
    #    Use the CRITsAPIResource to get our objects but provide the class to get
    #    the objects from.

    #    :param request: The incoming request.
    #    :type request: :class:`django.http.HttpRequest`
    #    :returns: Resulting objects in the specified format (JSON by default).

    #    """
    #    return super(DataDistributionResource, self).get_object_list(request, IP)

    def obj_get_list(self, request=None, **kwargs):
        """
        Handles GET requests and returns a list of data

        :param request:
        :param kwargs:
        :return: List of objects
        """
        obj = DataDistributionObject()
        obj.ip = "1.2.3.4"
        return [obj]