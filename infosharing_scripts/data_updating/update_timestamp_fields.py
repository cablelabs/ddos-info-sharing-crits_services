"""
Note: Before running script the first time, set status of each IP and Event object to "In Progress", and set the
timezone of CRITs to UTC.

The purpose of this script is to update any timestamp fields that originally used the current time in the server's
local timezone (MST). The values will be converted to UTC. These are the fields to update for each object:
IP: created, modified, Last Time Received
Event: created, modified

When an object is updated, the 'modified' time should be set to a legitimate UTC time.
"""
import os
from datetime import datetime, timedelta
from multiprocessing import Pool
import pytz
from tzlocal import get_localzone

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'

from crits.core.user_tools import get_user_organization
from crits.events.event import Event
from crits.ips.ip import IP


def local_time_to_utc(local_datetime):
    """
    Return the UTC time equivalent to the input local datetime.
    :param local_datetime: datetime object
    :return: datetime object
    """
    local_timezone = get_localzone()
    localized_time = local_timezone.localize(local_datetime)
    utc_time = localized_time.astimezone(pytz.utc)
    return utc_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def update_ip_object(ip_object):
    analyst = 'analysis_autofill'
    # Hard-coded increment of 7 hours to each timestamp, because the issue occurred on a machine running on MST (UTC-7).
    #ip_object.created += timedelta(hours=7)
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
        #last_time_seen_datetime += timedelta(hours=7)
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
    # Hard-coded increment of 7 hours to each timestamp, because the issue occurred on a machine running on MST (UTC-7).
    #event_object.created += timedelta(hours=7)
    event_object.created = local_time_to_utc(event_object.created)
    event_object.status = "Analyzed"
    event_object.save(username=analyst)
    return


ip_objects = IP.objects()
event_objects = Event.objects()
pool = Pool(10)
pool.map(update_ip_object, ip_objects)
pool.map(update_event_object, event_objects)
