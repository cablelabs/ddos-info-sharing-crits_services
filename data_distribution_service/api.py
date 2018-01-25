from tastypie import authorization
from tastypie.authentication import MultiAuthentication
from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.user_tools import get_user_organization
from handlers import collect_ip_data
from vocabulary import DistributionFields


class DataDistributionResource(CRITsAPIResource):
    """
    Class to handle everything related to the Data Ingester API.
    """

    class Meta:
        allowed_methods = ('get',)
        resource_name = "data_distribution_resource"
        collection_name = "outputData"
        excludes = ["id", "resource_uri", "unsupported_attrs"]
        limit = 20
        max_limit = 0
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

    def obj_get_list(self, request=None, **kwargs):
        """
        Returns the list of data to be sent in the 'outputData' field of a GET request.
        :param request:
        :param kwargs:
        :return: list of objects
        """
        actual_request = request
        if actual_request is None:
            # Request is likely contained in kwargs, not in request parameter.
            actual_request = kwargs['bundle'].request
        username = actual_request.GET.get('username', '')
        limit = actual_request.GET.get('limit', '20')
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            raise ValueError("'limit' parameter not an integer value.")
        modified_since = actual_request.GET.get('modifiedSince', None)
        sort_by = actual_request.GET.get('sortBy', None)
        sort_order = actual_request.GET.get('sortOrder', 'desc')
        sort_descending = True
        if sort_order == 'asc':
            sort_descending = False
        min_number_of_reporters = actual_request.GET.get('minNumberOfReporters', '0')
        try:
            min_number_of_reporters = int(min_number_of_reporters)
        except (TypeError, ValueError):
            raise ValueError("'minNumberOfReporters' parameter not an integer value.")
        result = collect_ip_data(username=username, limit=limit, modified_since=modified_since,
                                 sort_by=sort_by, sort_descending=sort_descending,
                                 min_number_of_reporters=min_number_of_reporters)
        objects = list(result)
        return objects

    def dehydrate(self, bundle):
        """
        Restructure fields in bundle so data is passed on correctly, remove fields that are null or are not something we
        intended on returning, and convert number fields from strings to integers or floats (depending on the field).
        :param bundle:
        :return:
        """
        bundle.data = bundle.obj
        fields_to_remove = []
        for field_name in bundle.data:
            if not bundle.data[field_name]:
                # Remove data for IP field if value is null or empty.
                fields_to_remove.append(field_name)
                continue
            try:
                variable_type = DistributionFields.api_field_to_variable_type(field_name)
            except ValueError:
                continue
            if variable_type == 'int':
                try:
                    bundle.data[field_name] = int(bundle.data[field_name])
                except (TypeError, ValueError):
                    pass
            elif variable_type == 'float':
                try:
                    bundle.data[field_name] = float(bundle.data[field_name])
                except (TypeError, ValueError):
                    pass
        for field in fields_to_remove:
            del bundle.data[field]
        EVENTS = DistributionFields.EVENTS
        if bundle.data.get(EVENTS) is not None:
            # Dehydrate each event.
            for i in range(0, len(bundle.data[EVENTS])):
                fields_to_remove = []
                for field_name in bundle.data[EVENTS][i]:
                    if not bundle.data[EVENTS][i][field_name]:
                        # Remove data for Event field if value is null or empty.
                        fields_to_remove.append(field_name)
                    elif field_name == DistributionFields.TIME_RECORDED:
                        time_recorded = bundle.data[EVENTS][i][DistributionFields.TIME_RECORDED]
                        bundle.data[EVENTS][i][DistributionFields.TIME_RECORDED] = time_recorded.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    else:
                        try:
                            variable_type = DistributionFields.api_field_to_variable_type(field_name)
                            if variable_type == 'int':
                                bundle.data[EVENTS][i][field_name] = int(bundle.data[EVENTS][i][field_name])
                            elif variable_type == 'float':
                                bundle.data[EVENTS][i][field_name] = float(bundle.data[EVENTS][i][field_name])
                        except (TypeError, ValueError):
                            continue
                for field in fields_to_remove:
                    del bundle.data[EVENTS][i][field]
        return bundle

    def alter_list_data_to_serialize(self, request, data):
        """
        Note: This function gets called after calling dehydrate() (above) on each bundle object, all within get_list()
        of resources.py of the tastypie library.
        :param request:
        :param data:
        :return:
        """
        del data['meta']
        username = request.GET.get('username', '')
        # TODO: Consider whether a user would ever make two submissions with two different sources, one of which is not
        # their main organization.
        source_name = get_user_organization(username)
        data['SourceName'] = source_name
        return data
