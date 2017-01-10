from mongoengine import Document, StringField, ListField, DynamicField, DictField
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.crits_mongoengine import CritsDocument
from crits.core.user_tools import user_sources
from crits.ips.ip import IP
from crits.vocabulary.objects import ObjectTypes

from handlers import add_or_update_ip_object_group


class DataIngesterObject(CritsDocument, Document):
    """
    Class to store data if we ever decide to make this support GET
    """
    provider_name = StringField()
    dis_data = DictField()

class DataIngesterResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.

    Currently supports POST.
    """

    class Meta:
        object_class = DataIngesterObject
        allowed_methods = ('get', 'post')
        resource_name = "data_ingester_resource"
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

    def obj_get_list(self, request=None, **kwargs):
        """
        Handles GET requests and returns a list of data

        :param request:
        :param kwargs:
        :return: List of objects
        """
        ip_object = IP.objects().first()
        obj = DataIngesterObject()
        for s in ip_object.source:
            obj.provider_name = str(s.name)

        obj.dis_data['IPaddress'] = ip_object.ip

        for o in ip_object.obj:
            if o.object_type == ObjectTypes.AS_NUMBER:
                obj.dis_data['SourceASN'] = o.value
            elif o.object_type == ObjectTypes.ALERT_TYPE:
                obj.dis_data['AlertType'] = o.value
            elif o.object_type == ObjectTypes.ATTACK_TYPE:
                obj.dis_data['AttackType'] = o.value
            elif o.object_type == ObjectTypes.CITY:
                obj.dis_data['City'] = o.value
            elif o.object_type == ObjectTypes.COUNTRY:
                obj.dis_data['Country'] = o.value
            elif o.object_type == ObjectTypes.NUMBER_OF_TIMES_SEEN:
                obj.dis_data['NumberOfTimes'] = o.value
            elif o.object_type == ObjectTypes.STATE:
                obj.dis_data['State'] = o.value
            elif o.object_type == ObjectTypes.TIME_FIRST_SEEN:
                obj.dis_data['FirstSeen'] = o.value
            elif o.object_type == ObjectTypes.TIME_LAST_SEEN:
                obj.dis_data['LastSeen'] = o.value
            elif o.object_type == ObjectTypes.TOTAL_BYTES_PER_SECOND:
                obj.dis_data['TotalBPS'] = o.value
            elif o.object_type == ObjectTypes.TOTAL_PACKETS_PER_SECOND:
                obj.dis_data['TotalPPS'] = o.value

        return [obj]

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
            response['message'] = "Error: Problem getting 'dis-data' field."
            self.crits_response(response, status=500)
            return
        if source is None:
            response['message'] = "Error: 'ProviderName' missing."
            self.crits_response(response, status=400)
            return

        try:
            sources = user_sources(analyst)
        except Exception:
            response['message'] = "Error: Problem getting user sources."
            self.crits_response(response, status=500)
            return
        if source not in sources:
            response['message'] = "Error: User not allowed to publish to source '" + str(source) + "'."
            self.crits_response(response, status=403)
            return

        try:
            ip_objects = bundle.data.get('dis-data', None)
        except Exception:
            response['message'] = "Error: Problem getting 'dis-data' field."
            self.crits_response(response, status=500)
            return
        if ip_objects is None:
            response['message'] = "Error: 'dis-data' missing."
            self.crits_response(response, status=400)
            return

        try:
            add_or_update_ip_object_group(analyst, source, ip_objects)
        except Exception, error:
            response['message'] = 'Error while saving IP data: ' + error.message
            self.crits_response(response, status=500)
            return

        response['message'] = 'All data has been saved!'
        response['return_code'] = 0
        self.crits_response(response)