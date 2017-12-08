from datetime import datetime
import pickle
import pytz
import re
from tzlocal import get_localzone
from pymongo import MongoClient

sample_size = 1000

client = MongoClient()
ips = client.crits.ips
events = client.crits.events
number_of_ips = ips.count()
number_of_events = events.count()


def local_time_to_utc(local_datetime):
    """
    Return the UTC time equivalent to the input local datetime.
    :param local_datetime: datetime object
    :return: datetime object
    """
    local_timezone = get_localzone()
    localized_time = local_timezone.localize(local_datetime)
    utc_time = localized_time.astimezone(pytz.utc)
    return utc_time


def is_new_date_correct(old_datetime, new_datetime):
    """
    Confirm that old_datetime corrected for timezone difference equals new_datetime.
    :param old_datetime:
    :param new_datetime:
    :return:
    """
    updated_datetime = local_time_to_utc(old_datetime)
    saved_datetime = pytz.utc.localize(new_datetime)
    return updated_datetime == saved_datetime


def new_title(title):
    timestamp_string = timestamp_str_from_title(title)
    try:
        timestamp_datetime = datetime.strptime(timestamp_string, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return title
    timestamp_datetime = local_time_to_utc(timestamp_datetime)
    new_timestamp_string = timestamp_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    title_split = title.split('Time')
    title_prefix = title_split[0]
    new_title_result = title_prefix + 'Time:[' + new_timestamp_string + ']'
    return new_title_result


def timestamp_str_from_title(title):
    # Extract timestamp string from input title of some Event object
    search_query = "Time:\[.*\]"
    results = re.findall(search_query, title)
    main_result = results[0]
    split1 = main_result.split('Time:[')
    main_result = filter(None, split1)[0]
    split2 = main_result.split(']')
    main_result = filter(None, split2)[0]
    return main_result


def compare_documents(old_doc, new_doc):
    """
    Make sure that all timestamps in new_doc are corrected, with respect to previous values in old_doc.
    :param old_doc: Document as it was before the timestamp correction script was run.
    :type old_doc: dict
    :param new_doc: Document as it is after running the timestamp correction script.
    :type new_doc: dict
    :return:
    """
    if not is_new_date_correct(old_doc['created'], new_doc['created']):
        return False
    if 'title' in old_doc:
        updated_title = new_title(old_doc['title'])
        if not updated_title == new_doc['title']:
            return False
    for old_relationship in old_doc['relationships']:
        found_match = False
        for new_relationship in new_doc['relationships']:
            if old_relationship['value'] == new_relationship['value']:
                found_match = True
                if not is_new_date_correct(old_relationship['relationship_date'], new_relationship['relationship_date']):
                    return False
                if not is_new_date_correct(old_relationship['date'], new_relationship['date']):
                    return False
                break
        if not found_match:
            return False
    for old_source in old_doc['source']:
        found_match = False
        for new_source in new_doc['source']:
            if old_source['name'] == new_source['name']:
                found_match = True
                new_instances = new_source['instances'][:]
                for old_instance in old_source['instances']:
                    corrected_date = local_time_to_utc(old_instance['date'])
                    matching_instance = None
                    for new_instance in new_instances:
                        localized_date = pytz.utc.localize(new_instance['date'])
                        if corrected_date == localized_date:
                            matching_instance = new_instance
                            break
                    if matching_instance is None:
                        return False
                    new_instances.remove(matching_instance)
                break
        if not found_match:
            return False
    for old_object in old_doc['objects']:
        found_match = False
        for new_object in new_doc['objects']:
            if old_object['type'] == new_object['type']:
                # Extra checks for specific object types.
                if old_object['type'] == 'Last Time Received':
                    last_time_seen = old_object['value']
                    try:
                        last_time_seen_datetime = datetime.strptime(last_time_seen, "%Y-%m-%dT%H:%M:%S.%fZ")
                    except ValueError:
                        continue
                    last_time_seen_datetime = local_time_to_utc(last_time_seen_datetime)
                    updated_last_time_seen = last_time_seen_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    if updated_last_time_seen != new_object['value']:
                        continue
                elif old_object['type'] == 'Attack Start Time' or old_object['type'] == 'Attack Stop Time':
                    # Add "Z" to the end if there is no timezone, and replace lowercase "z" with uppercase "Z".
                    attack_time = old_object['value']
                    attack_time_split = attack_time.split('z')
                    attack_time = filter(None, attack_time_split)[0]
                    if "Z" not in attack_time:
                        attack_time += "Z"
                    if attack_time != new_object['value']:
                        continue
                # For all other types of objects, the values should be the same.
                elif old_object['value'] != new_object['value']:
                    continue
                # Confirm that all timestamps of all instances of all sources of the object are updated.
                all_timestamps_correct = True
                for old_source in old_object['source']:
                    found_source_match = False
                    for new_source in new_object['source']:
                        if old_source['name'] == new_source['name']:
                            new_instances = new_source['instances'][:]
                            for old_instance in old_source['instances']:
                                corrected_date = local_time_to_utc(old_instance['date'])
                                matching_instance = None
                                for new_instance in new_instances:
                                    localized_date = pytz.utc.localize(new_instance['date'])
                                    if corrected_date == localized_date:
                                        matching_instance = new_instance
                                        break
                                if matching_instance is None:
                                    continue
                                new_instances.remove(matching_instance)
                            found_source_match = True
                            break
                    if not found_source_match:
                        all_timestamps_correct = False
                        break
                found_match = all_timestamps_correct
                if found_match:
                    break
        if not found_match:
            return False
    return True


with open('samples_before.pickle', 'rb') as samples_before_file:
    # The first 'sample_size' many objects loaded should be IP objects.
    for i in range(sample_size):
        old_ip_document = pickle.load(samples_before_file)
        new_ip_document = ips.find_one({'_id': old_ip_document['_id']})
        try:
            assert(compare_documents(old_ip_document, new_ip_document))
        except AssertionError, e:
            print e

    # The next 'sample_size' many objects loaded should be Event objects.
    for j in range(sample_size):
        old_event_object = pickle.load(samples_before_file)
        new_event_object = events.find_one({'_id': old_event_object['_id']})
        try:
            assert(compare_documents(old_event_object, new_event_object))
        except AssertionError, e:
            print e
