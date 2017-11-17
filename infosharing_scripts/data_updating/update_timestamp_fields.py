"""
Note: Before running script the first time, set status of each IP and Event object to "In Progress", and set the
timezone of CRITs to UTC.

The purpose of this script is to update any timestamp fields that originally used the current time in the server's
local timezone (MST). The values will be converted to UTC. These are the fields to update for each object:
IP: created, modified, Last Time Received
Event: created, modified

When new values are saved to an object, the 'modified' time of that object should automatically be set to a legitimate
UTC time (specifically the time when the values were saved).
"""

import os
from datetime import datetime
from multiprocessing import Pool
import pytz
from tzlocal import get_localzone
import pandas as pd

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'

# This is weird, but for some reason if I don't call get_localzone() before importing from CRITs, it will return "UTC"
# instead of the actual timezone of the machine (which in our case should be "America/Denver"). Without this line,
# the local_time_to_utc() function would just return the same value as the input.
print get_localzone()

from crits.core.user_tools import get_user_organization
from crits.events.event import Event
from crits.ips.ip import IP


# Function borrowed from the internet
def iterator2dataframes(iterator, chunk_size):
    """
    Turn an iterator into multiple small pandas.DataFrame objects. This is a balance between memory and efficiency.
    :param iterator:
    :param chunk_size:
    :return: pandas.DataFrame
    """
    records = []
    frames = []
    for i, record in enumerate(iterator):
        records.append(record)
        if i % chunk_size == chunk_size - 1:
            frames.append(pd.DataFrame(records))
            records = []
    if records:
        frames.append(pd.DataFrame(records))
    return pd.concat(frames)


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


def update_ip_object(ip_object):
    analyst = 'analysis_autofill'
    ip_object.created = local_time_to_utc(ip_object.created)
    # To prevent skipping objects while iterating through sub-objects, store list of objects to remove later.
    previous_object_values = []
    for o in ip_object.obj:
        if o.object_type == 'Last Time Received':
            previous_object_values.append(o.value)
    last_time_seen = ''
    for previous_value in previous_object_values:
        last_time_seen = previous_value
        ip_object.remove_object('Last Time Received', previous_value)
    try:
        last_time_seen_datetime = datetime.strptime(last_time_seen, "%Y-%m-%dT%H:%M:%S.%fZ")
        last_time_seen_datetime = local_time_to_utc(last_time_seen_datetime)
        last_time_seen = last_time_seen_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        ip_object.add_object('Last Time Received', last_time_seen, get_user_organization(analyst), '', '', analyst)
    except ValueError:
        pass
    ip_object.status = "Analyzed"
    ip_object.save(username=analyst)
    return


def update_event_object(event_object):
    analyst = 'analysis_autofill'
    event_object.created = local_time_to_utc(event_object.created)
    event_object.status = "Analyzed"
    event_object.save(username=analyst)
    return


ip_objects = IP.objects(status='In Progress')
start_time = datetime.now()
ip_objects_list = list(ip_objects)
duration = datetime.now() - start_time
print "Time to convert IPs to list:", duration

event_objects = Event.objects(status='In Progress')
start_time = datetime.now()
event_objects_list = list(event_objects)
duration = datetime.now() - start_time
print "Time to convert Events to list:", duration

pool = Pool(10)
print "Pool initialized."
start_time = datetime.now()
#for ip_object in ip_objects:
#    update_ip_object(ip_object)
pool.map(update_ip_object, ip_objects_list)
duration = datetime.now() - start_time
print "Time to update IPs:", duration
print "Number of IPs:", len(ip_objects_list)

start_time = datetime.now()
#for event_object in event_objects:
#    update_event_object(event_object)
pool.map(update_event_object, event_objects_list)
duration = datetime.now() - start_time
print "Time to update Events:", duration
print "Number of Events:", len(event_objects_list)
pool.close()
