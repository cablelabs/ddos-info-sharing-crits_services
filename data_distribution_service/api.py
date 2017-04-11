from datetime import datetime
from tastypie import authorization
from tastypie.authentication import MultiAuthentication

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.user_tools import get_user_organization, user_sources
from crits.ips.ip import IP
from crits.vocabulary.objects import ObjectTypes

from DataDistributionObject import DataDistributionObject
from handlers import create_raw_query, get_limit


class DataDistributionResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.

    Currently supports GET.
    """
    def __init__(self):
        super(DataDistributionResource, self).__init__()
        self.request = None
        # Set parameters of GET call internally
        #self.limit = 20
        #self.sortBy = ''
        #self.sortOrder = ''
        #self.createdSince = ''
        #self.modifiedSince = ''
        self.aggregation_pipeline = []
        self.output_field_to_object_type = {
            'numberOfTimesSeen': ObjectTypes.NUMBER_OF_TIMES_SEEN,
            'firstTimeSeen': ObjectTypes.TIME_FIRST_SEEN,
            'lastTimeSeen': ObjectTypes.TIME_LAST_SEEN,
            'totalBPS': ObjectTypes.TOTAL_BYTES_PER_SECOND,
            'totalPPS': ObjectTypes.TOTAL_PACKETS_PER_SECOND,
            'peakBPS': '',
            'peakPPS': '',
            'City': ObjectTypes.CITY,
            'State': ObjectTypes.STATE,
            'Country': ObjectTypes.COUNTRY,
            'attackTypes': ObjectTypes.ATTACK_TYPE
        }
        self.variable_name_to_output_field = {
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
        fields_to_remove = []
        bundle.data = bundle.obj
        all_output_fields = self.output_field_to_object_type.keys()
        all_output_fields.append('IPaddress')
        for key in bundle.data:
            if not (bundle.data[key] and key in all_output_fields):
                fields_to_remove.append(key)
        # Remove fields that have null values.
        for field in fields_to_remove:
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
        result = self.do_aggregation()
        return list(result)

    def do_aggregation(self):
        self.aggregation_pipeline = []
        self._add_source_filter_to_pipeline()
        self._add_field_projections_to_pipeline()
        self._add_created_filter_to_pipeline()
        self._add_modified_filter_to_pipeline()
        self._add_sort_to_pipeline()
        self._add_limit_to_pipeline()
        value = IP.objects.filter().aggregate(*self.aggregation_pipeline, useCursor=False)
        return value

    # Filter on entries with at least one source in the list of sources the user has access to.
    def _add_source_filter_to_pipeline(self):
        username = self.request.GET.get('username', '')
        source_list = user_sources(username)
        match = { '$match': {'source.name': {'$in': source_list}} }
        self.aggregation_pipeline.append(match)

    def _add_field_projections_to_pipeline(self):
        project = {'$project': { '_id': 0, 'IPaddress': '$ip'} }
        for output_field, object_type in self.output_field_to_object_type.items():
            project['$project'][output_field] = {
                '$let': {
                    'vars': {
                        'one_obj': {
                            '$arrayElemAt': [
                                {
                                    '$filter': {
                                        'input': '$objects',
                                        'as': 'obj',
                                        'cond': {'$eq': ['$$obj.type', object_type]}
                                    }
                                },
                                0
                            ]
                        }
                    },
                    'in': '$$one_obj.value'
                }
            }
        self.aggregation_pipeline.append(project)

    # Filter on entries created since the 'createdSince' time.
    def _add_created_filter_to_pipeline(self):
        created_since = self.request.GET.get('createdSince', '')
        if created_since:
            try:
                created_since_datetime = datetime.strptime(created_since, "%Y-%m-%dT%H:%M:%S.%fZ")
            except (ValueError):
                try:
                    created_since_datetime = datetime.strptime(created_since, "%Y-%m-%d")
                except (ValueError):
                    raise ValueError("'createdSince' time not a properly formatted ISO string.")
            match = { '$match': {'firstTimeSeen': {'$gte': created_since_datetime}} }
            self.aggregation_pipeline.append(match)

    # Filter on entries modified since the 'modifiedSince' time.
    def _add_modified_filter_to_pipeline(self):
        modified_since = self.request.GET.get('modifiedSince', '')
        if modified_since:
            try:
                modified_since_datetime = datetime.strptime(modified_since, "%Y-%m-%dT%H:%M:%S.%fZ")
            except (ValueError):
                try:
                    modified_since_datetime = datetime.strptime(modified_since, "%Y-%m-%d")
                except (ValueError):
                    raise ValueError("'modifiedSince' time not a properly formatted ISO string.")
            match = { '$match': {'lastTimeSeen': {'$gte': modified_since_datetime}} }
            self.aggregation_pipeline.append(match)

    def _add_sort_to_pipeline(self):
        sort_by = self.request.GET.get('sortBy', '')
        if sort_by:
            field_name = DataDistributionObject.get_field_name_from_display_name(sort_by)
            if not field_name:
                raise ValueError("'sortBy' parameter is not a valid field to sort on.")
            # Default to descending order
            sort_order = self.request.GET.get('sortOrder', 'desc')
            sort_order_number = -1 if (sort_order == 'desc') else 1
            sort = { '$sort': {sort_by: sort_order_number} }
            self.aggregation_pipeline.append(sort)

    def _add_limit_to_pipeline(self):
        input_limit = self.request.GET.get('limit', '20')
        try:
            limit_integer = int(input_limit)
            return limit_integer
        except (TypeError, ValueError):
            raise ValueError("'limit' field set to invalid value. Must be integer.")

        limit = { '$limit': limit_integer }
        self.aggregation_pipeline.append(limit)


    ### DEPRECATED BELOW HERE ###

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