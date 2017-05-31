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
