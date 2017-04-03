from datetime import datetime
from pymongo import MongoClient

from crits.core.user_tools import user_sources


def create_raw_query(request):
    """
    :param request:
    :return: dict
    """
    raw_query = {}
    # Use only entries with at least one source in the list of sources the user has access to.
    username = request.GET.get('username', '')
    source_list = user_sources(username)
    raw_query['source.name'] = {'$in': source_list}
    # Filter on entries created since the 'createdSince' time.
    created_since = request.GET.get('createdSince', '')
    if created_since:
        created_since_datetime = None
        try:
            created_since_datetime = datetime.strptime(created_since, "%Y-%m-%dT%H:%M:%S.%fZ")
        except (ValueError):
            try:
                created_since_datetime = datetime.strptime(created_since, "%Y-%m-%d")
            except (ValueError):
                pass
        if not created_since_datetime:
            raise ValueError("'createdSince' time not a properly formatted ISO string.")
        raw_query['created'] = {'$gte': created_since_datetime}

    # Filter on entries modified since the 'modifiedSince' time.
    modified_since = request.GET.get('modifiedSince', '')
    if modified_since:
        modified_since_datetime = None
        try:
            modified_since_datetime = datetime.strptime(modified_since, "%Y-%m-%dT%H:%M:%S.%fZ")
        except (ValueError):
            try:
                modified_since_datetime = datetime.strptime(modified_since, "%Y-%m-%d")
            except (ValueError):
                pass
        if not modified_since_datetime:
            raise ValueError("'modifiedSince' time not a properly formatted ISO string.")
        raw_query['modified'] = {'$gte': modified_since_datetime}
    return raw_query

def get_limit(request):
    input_limit = request.GET.get('limit', '')
    if input_limit:
        try:
            limit_integer = int(input_limit)
            return limit_integer
        except (TypeError, ValueError):
            raise ValueError("'limit' field set to invalid value. Must be integer.")
    # return an arbitrary default value
    return 20



# SHOULD NOT BE USED
def sort_ip_entries(self, request, ip_entries):
    # Mapping of possible inputs for "sortBy" field to the names of the fields that are stored as separate objects
    # within the "objects" field of an IP.
    inputs_to_nested_object_fields = {
        "ASName": "AS Name",
        "ASNumber": "AS Number",
        "sourcePort": "Source Port",
        "destinationPort": "Destination Port",
        "numberOfTimesSeen": "Number of Times Seen",
        "firstTimeSeen": "Time First Seen",
        "lastTimeSeen": "Time Last Seen",
        "totalBPS": "Total BPS",
        "totalPPS": "Total PPS",
        "peakBPS": "Peak BPS",
        "peakPPS": "Peak PPS",
        "extra": "Extra",
        "city": "City",
        "state": "State",
        "country": "Country",
        "latitude": "Latitude",
        "longitude": "Longitude",
        "attackTypes": "Attack Types"
    }

    sort_by = request.GET.get('sortBy', '')
    sort_order = request.GET.get('sortOrder', 'desc')
    if sort_by:
        if sort_by in inputs_to_nested_object_fields:
            client = MongoClient()
            db = client.crits
            nested_field = inputs_to_nested_object_fields[sort_by]
            pipeline = [
                {'$unwind': '$objects'},
                {'$match': {'objects.type': nested_field}},
                {'$group': {'_id': '$ip', nested_field: {"$first": '$objects.value'}}},
                {'$sort': {nested_field: 1}}
            ]
            # this only contains the "nested_field" and IP addresses for all entries, sorted by the "nested_field".
            # TODO: I want the original objects sorted by the "nested_field".
            # TODO: Also, I only want to sort the input ip_entries, whereas this currently sorts ALL entries in the
            # IP collection.
            aggregation = db.ips.aggregate(pipeline)
            if aggregation:
                result = aggregation['result']
            new_ip_entries = None
            for result_entry in result:
                next_ip_entry = ip_entries.filter(ip=result_entry['_id'])
                if next_ip_entry:
                    if not new_ip_entries:
                        new_ip_entries = next_ip_entry
                    else:
                        new_ip_entries = new_ip_entries.merge(next_ip_entry)
            return new_ip_entries
            # Can't do it this way below without MongoEngine 0.9 or above. Currently 0.8.8
            # ip_entries = ip_entries.aggregate(pipeline)
        else:
            sort_query_string = sort_by
            if sort_order == 'desc':
                sort_query_string = '-' + sort_query_string
            ip_entries = ip_entries.order_by(sort_query_string)

    return ip_entries

# project = {
        #     '$ip': 1,
        #     'numTimesSeen':
        #         {
        #             '$cond': { 'if': { '$eq': [] }, 'then': '', 'else': ''}
        #         }
        # }
        #
        # IP.aggregate([
        #     {'$unwind': '$objects'},
        #     {'$project': {'$ip': 1, '$type': '$value'}},
        #     {'$group': {'ip': '$ip', 'numTimesSeen': 'Number of Times Seen'}}
        # ])

        # IP.aggregate([
        #     { '$project':
        #         { 'newObjects':
        #             { '$map':
        #                 {
        #                     'input': '$objects',
        #                     'as': 'obj',
        #                     'in':
        #                         {
        #                             '$cond': { 'if': {'$eq': ['$$obj.key', 'Number of Times']}}
        #                         }
        #                 }
        #             }
        #         }
        #     }
        # ])