from django.core.urlresolvers import reverse
from mongoengine import Document, ListField, DynamicField, DictField

from tastypie import authorization
from tastypie.authentication import MultiAuthentication
from tastypie.exceptions import BadRequest
from tastypie_mongoengine.resources import ListQuerySet

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.crits_mongoengine import CritsDocument
from . import handlers
from .__init__ import DataIngesterService

import weakref

class DataIngesterObject(CritsDocument, Document):
    """
    Class to store data
    """

    whowasit = ListField(DynamicField(DictField))
    money = ListField(DynamicField(DictField))


class DataIngesterResource(CRITsAPIResource):

    service_object = None

    class Meta:
        object_class = DataIngesterObject
        allowed_methods = ('get','post',)
        resource_name = "data_ingester_resource"
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

    #def __init__(self):
        #self.shelve_file = shelve.open("/home/infosharing/Documents/Storage")
        #self.service_object = self.shelve_file["service_object"]


    def obj_create(self, bundle, **kwargs):
        """
        Handles creating Data Ingester Identifiers through the API. Handles POST requests.

        :param bundle: Bundle containing the information to create the Identifier.
        :type bundle: Tastypie Bundle object.
        :returns: HttpResponse object.
        """

        # TODO: Should I return an HttpResponse object as mentioned in these comments I copied?
        # if request.method == "POST" and request.is_ajax():

        incoming_data = {}
        data_fields = ['City', 'AlertType', 'Vendor', 'Country', 'TotalPPS', 'State',
                       'TotalBPS', 'LastSeen', 'NumberOfTimes', 'Type', 'ASN', 'FirstSeen',
                       'ip', 'ip_type', 'source', 'source_method', 'source_reference',
                       'campaign', 'confidence', 'bucket_list', 'ticket', 'is_add_indicator',
                       'indicator_reference', 'misc'
        ]
        for field in data_fields:
            try:
                incoming_data[field] = bundle.data.get(field, None)
            except Exception, e:
                response = {
                    'return_code': 0,
                    'type': 'DataIngesterObject',
                    'message': 'There was a problem getting the inputs.'
                }
                self.crits_response(response)

        incoming_data['analyst'] = bundle.request.user.username

        response = {
            'return_code': 0,
            'type': 'DataIngesterObject',
            'message': 'Data has been saved!'
        }

        try:
            handlers.save_incoming_data(incoming_data)
            results_data = {}
            data_fields = ['City', 'AlertType', 'Vendor', 'Country', 'TotalPPS', 'State',
                           'TotalBPS', 'LastSeen', 'NumberOfTimes', 'Type', 'ASN', 'FirstSeen']
            for field in data_fields:
                results_data[field] = incoming_data.get(field, None)
                # ip_object[field] = incoming_data.get(field, None)
                # ip_object[field] = value

            #service_objects = DataIngesterService.getinstances()
            #for service_obj in service_objects:
            #    self.service_object._add_result("Extra Data", "Extra data for IP " + bundle.data.get('ip', None) + ".",
            #                                    data=results_data)

            #if self.service_object is not None:
            #    self.service_object._add_result("Extra Data", "Extra data for IP " + bundle.data.get('ip', None) + ".", data=results_data)

            #all_instances = DataIngesterService.get_instances()
            DataIngesterService().run("IP", results_data)

            #for instance in all_instances:
            #instance._add_result("Extra Data", "Extra data for IP " + bundle.data.get('ip', None) + ".",
            #                     data=results_data)
        except Exception, e:
            response = {
                'return_code': 1,
                'type': 'DataIngesterObject',
                'message': 'An error occured. The data has not been saved.'
            }

        self.crits_response(response)


        #content = {'return_code': 1,
        #           'type': 'DataIngesterObject',
        #           'message': 'Data has been saved!',
        #           'what you said': bundle.data.get('what_he_said', None)}
        #self.crits_response(content)

    def obj_get_list(self, request=None, **kwargs):
        """
        Handles simple GET requests.

        :param request:
        :param kwargs:
        :return:
        """

        return self.get_object_list(request)

    def get_object_list(self, request):
        """
        Expose the objects generated in the Data Ingester Service via an API.

        :param request: The incoming request.
        :type request: :class:`django.http.HttpRequest`
        :returns: Resulting objects in the specified format (JSON by default).
        """

        #content = {'chicken': 1,
        #           'potato': 'Good job!'}
        content = DataIngesterObject()
        content.whowasit = "Dio"
        content.money = "All of it!"
        return [content]