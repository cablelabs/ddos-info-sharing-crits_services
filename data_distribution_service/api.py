from mongoengine import Document, FloatField, IntField, StringField
from tastypie import authorization
from tastypie.authentication import MultiAuthentication
import pymongo

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.crits_mongoengine import CritsDocument
from crits.core.user_tools import get_user_organization, user_sources
from crits.ips.ip import IP
from crits.vocabulary.objects import ObjectTypes

from django.db.models import F



class DataDistributionObject(CritsDocument, Document):
    """
    Class to store data for GET requests.
    """
    ip_address = StringField()
    number_of_times = IntField()
    first_seen = StringField()
    last_seen = StringField()
    total_bps = FloatField()
    total_pps = FloatField()
    peak_bps = FloatField()
    peak_pps = FloatField()
    city = StringField()
    state = StringField()
    country = StringField()
    latitude = FloatField()
    longitude = FloatField()
    attack_types = StringField()


class DataDistributionResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.

    Currently supports GET.
    """
    def __init__(self):
        super(DataDistributionResource, self).__init__()
        self.field_name_to_display_name = {
            'ip_address': 'IPaddress',
            'number_of_times': 'numberOfTimesSeen',
            'first_seen': 'firstTimeSeen',
            'last_seen': 'lastTimeSeen',
            'total_bps': 'totalBPS',
            'total_pps': 'totalPPS',
            'peak_bps': 'peakBPS',
            'peak_pps': 'peakPPS',
            'city': 'City',
            'state': 'State',
            'country': 'Country',
            'latitude': 'Latitude',
            'longitude': 'Longitude',
            'attack_types': 'attackTypes'
        }
        self.default_limit = 20

    class Meta:
        object_class = DataDistributionObject
        allowed_methods = ('get')
        resource_name = "data_distribution_resource"
        collection_name = "dis-data"
        excludes = ["id", "resource_uri", "unsupported_attrs"]
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

    def alter_list_data_to_serialize(self, request, data):
        del data['meta']
        username = request.GET.get('username', '')
        source_name = get_user_organization(username)
        data['SourceName'] = source_name
        return data

    def dehydrate(self, bundle):
        for key, value in self.field_name_to_display_name.items():
            if key in bundle.data:
                if bundle.data[key]:
                    bundle.data[value] = bundle.data.pop(key)
                else:
                    del bundle.data[key]
        return bundle

    def obj_get_list(self, request=None, **kwargs):
        """
        Returns the list of data returned in the 'objects' field of a GET request, but in our case we rename 'objects'
         to 'dis-data'.

        :param request:
        :param kwargs:
        :return: List of objects
        """
        if not request:
            request = kwargs['bundle'].request
        username = request.GET.get('username', '')
        limit = self.default_limit
        try:
            limit = int(request.GET.get('limit', self.default_limit))
        except (TypeError, ValueError):
            pass
        return self.create_list_from_ip_objects(username, limit)

    # CURRENTLY UNUSED
    def create_list_from_mongo_client(self, username):
        client = pymongo.MongoClient()
        ips = client.crits.ips
        all_ip_entries = ips.find()
        return_list = []
        for ip_entry in all_ip_entries:
            # Create new object with data only if at least one of the sources in the IP object is a source of the user.
            if self.is_ip_in_users_network(ip_entry, username):
                new_obj = DataDistributionObject()
                new_obj.ip_address = ip_entry['ip']
                for o in ip_entry['objects']:
                    if o['type'] == ObjectTypes.ATTACK_TYPE:
                        new_obj.attack_types = o['value']
                    elif o['type'] == ObjectTypes.CITY:
                        new_obj.city = o['value']
                    elif o['type'] == ObjectTypes.COUNTRY:
                        new_obj.country = o['value']
                    elif o['type'] == ObjectTypes.NUMBER_OF_TIMES_SEEN:
                        new_obj.number_of_times = o['value']
                    elif o['type'] == ObjectTypes.STATE:
                        new_obj.state = o['value']
                    elif o['type'] == ObjectTypes.TIME_FIRST_SEEN:
                        new_obj.first_seen = o['value']
                    elif o['type'] == ObjectTypes.TIME_LAST_SEEN:
                        new_obj.last_seen = o['value']
                    elif o['type'] == ObjectTypes.TOTAL_BYTES_PER_SECOND:
                        new_obj.total_bps = o['value']
                    elif o['type'] == ObjectTypes.TOTAL_PACKETS_PER_SECOND:
                        new_obj.total_pps = o['value']
                return_list.append(new_obj)
        return return_list

    # Returns true iff at least one of the sources in the ip_entry is a source of the user with the input name.
    def is_ip_in_users_network(self, ip_entry, username):
        #return True
        ip_sources = ip_entry['source']
        user_source_name_list = user_sources(username)
        for source in ip_sources:
            if source['name'] in user_source_name_list:
                return True
        return False

    # Portions of code in this function are based on get_object_list() in core/api.py
    def create_list_from_ip_objects(self, username, limit=0):
        querydict = {}
        # Use only entries with at least one source in the list of sources the user has access to.
        source_list = user_sources(username)
        querydict['source.name'] = {'$in': source_list}
        all_ip_entries = IP.objects(__raw__=querydict)[:limit]
        return_list = []
        for ip_entry in all_ip_entries:
            new_obj = DataDistributionObject()
            new_obj.ip_address = ip_entry.ip
            for o in ip_entry.obj:
                if o.object_type == ObjectTypes.ATTACK_TYPE:
                    new_obj.attack_types = o.value
                elif o.object_type == ObjectTypes.CITY:
                    new_obj.city = o.value
                elif o.object_type == ObjectTypes.COUNTRY:
                    new_obj.country = o.value
                elif o.object_type == ObjectTypes.NUMBER_OF_TIMES_SEEN:
                    new_obj.number_of_times = o.value
                elif o.object_type == ObjectTypes.STATE:
                    new_obj.state = o.value
                elif o.object_type == ObjectTypes.TIME_FIRST_SEEN:
                    new_obj.first_seen = o.value
                elif o.object_type == ObjectTypes.TIME_LAST_SEEN:
                    new_obj.last_seen = o.value
                elif o.object_type == ObjectTypes.TOTAL_BYTES_PER_SECOND:
                    new_obj.total_bps = o.value
                elif o.object_type == ObjectTypes.TOTAL_PACKETS_PER_SECOND:
                    new_obj.total_pps = o.value
            return_list.append(new_obj)
        return return_list