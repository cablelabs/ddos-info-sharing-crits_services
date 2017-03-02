from mongoengine import Document, FloatField, IntField, StringField
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.crits_mongoengine import CritsDocument
from crits.core.user_tools import get_user_organization
from crits.ips.ip import IP
from crits.vocabulary.objects import ObjectTypes

from handlers import create_raw_query, get_limit


class DataDistributionObject(CritsDocument, Document):
    """
    Class to store data for GET requests.
    """
    ip_address = StringField(verbose_name='IPaddress')
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

    field_name_to_display_mapping = {
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

    @classmethod
    def get_display_from_field_name(cls, field_name):
        if field_name not in cls.field_name_to_display_mapping:
            return None
        return cls.field_name_to_display_mapping[field_name]

    @classmethod
    def get_field_name_from_display_name(cls, input_display_name):
        for field_name, display_name in cls.field_name_to_display_mapping.items():
            if display_name == input_display_name:
                return field_name
        return None

    @classmethod
    def get_all_display_names(cls):
        return cls.field_name_to_display_mapping.values()

class DataDistributionResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.

    Currently supports GET.
    """
    def __init__(self):
        super(DataDistributionResource, self).__init__()
        self.request = None

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
        null_fields = []
        for field_name in bundle.data:
            if bundle.data[field_name]:
                display_name = DataDistributionObject.get_display_from_field_name(field_name)
                # Rename field to desired format.
                if display_name:
                    bundle.data[display_name] = bundle.data.pop(field_name)
            else:
                null_fields.append(field_name)
        # Remove fields that have null values.
        for field in null_fields:
            del bundle.data[field]
        return bundle

    # TODO: add support for searching on particular fields like FirstSeen, LastSeen, etc.
    def obj_get_list(self, request=None, **kwargs):
        """
        Returns the list of data returned in the 'objects' field of a GET request, but in our case we rename 'objects'
         to 'dis-data'.

        Allowed parameters in request:
        "limit", "sortBy", "sortOrder", "createdSince", "modifiedSince"

        :param request:
        :param kwargs:
        :return: List of objects
        """
        if request:
            self.request = request
        else:
            self.request = kwargs['bundle'].request

        raw_query = create_raw_query(self.request)
        limit = get_limit(self.request)
        ip_entries = IP.objects(__raw__=raw_query)
        data_distribution_object_list = self.create_data_distribution_object_list(ip_entries)
        return data_distribution_object_list[:limit]

    def create_data_distribution_object_list(self, ip_entries):
        object_list = []
        for ip_entry in ip_entries:
            new_object = self.create_data_distribution_object_from_ip_entry(ip_entry)
            object_list.append(new_object)
        sorted_object_list = self.sorted_data_distribution_object_list(object_list)
        return sorted_object_list

    def create_data_distribution_object_from_ip_entry(self, ip_entry):
        """
        Portions of code in this function are based on get_object_list() in core/api.py
        """
        new_object = DataDistributionObject()
        new_object.ip_address = ip_entry.ip
        for o in ip_entry.obj:
            if o.object_type == ObjectTypes.ATTACK_TYPE:
                new_object.attack_types = o.value
            elif o.object_type == ObjectTypes.CITY:
                new_object.city = o.value
            elif o.object_type == ObjectTypes.COUNTRY:
                new_object.country = o.value
            elif o.object_type == ObjectTypes.NUMBER_OF_TIMES_SEEN:
                new_object.number_of_times = o.value
            elif o.object_type == ObjectTypes.STATE:
                new_object.state = o.value
            elif o.object_type == ObjectTypes.TIME_FIRST_SEEN:
                new_object.first_seen = o.value
            elif o.object_type == ObjectTypes.TIME_LAST_SEEN:
                new_object.last_seen = o.value
            elif o.object_type == ObjectTypes.TOTAL_BYTES_PER_SECOND:
                new_object.total_bps = o.value
            elif o.object_type == ObjectTypes.TOTAL_PACKETS_PER_SECOND:
                new_object.total_pps = o.value
        return new_object

    def sorted_data_distribution_object_list(self, object_list):
        """
        Sort the input list of objects.
        :param object_list:
        :return:
        """
        sort_by = self.request.GET.get('sortBy', '')
        if sort_by:
            field_name = DataDistributionObject.get_field_name_from_display_name(sort_by)
            if not field_name:
                raise ValueError("'sortBy' parameter is not a valid field to sort on.")
            sort_order = self.request.GET.get('sortOrder', 'desc')
            is_reverse = (sort_order == 'desc')
            sorted_object_list = sorted(object_list, key=lambda x: self.get_field_from_object(x, field_name), reverse=is_reverse)
            return sorted_object_list
        return object_list

    def get_field_from_object(self, obj, field_name):
        value = getattr(obj, field_name)
        try:
            # TODO: will we ever use float values, or only integer values?
            int_value = int(value)
            return int_value
        except (TypeError, ValueError):
            return value