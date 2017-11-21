"""
Note: Before running script the first time, set status of each IP and Event object to "In Progress", and set the
timezone of CRITs to UTC.

The purpose of this script is to update any timestamp fields that originally used the current time in the server's
local timezone (MST). The values will be converted to UTC. These are the fields to update for each object:
IP: created, modified, Last Time Received
Event: created, modified

When new values are saved to an object, the 'modified' time of that object will be set to a legitimate UTC time
(specifically the time when the values were saved).
"""
from datetime import datetime
import pytz
from tzlocal import get_localzone
from pymongo import MongoClient
import pendulum


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

print "Script Start (UTC):", pendulum.now('UTC')
in_progress_filter = {'status': 'In Progress'}
client = MongoClient()
ips = client.crits.ips
ip_objects = ips.find(filter=in_progress_filter)
number_of_ips = 0

start_time = datetime.now()
for ip_object in ip_objects:
    new_created_date = local_time_to_utc(ip_object['created'])
    new_last_time_seen_object = None
    for obj in ip_object['objects']:
        if obj['type'] == 'Last Time Received':
            last_time_seen = obj['value']
            last_time_seen_datetime = datetime.strptime(last_time_seen, "%Y-%m-%dT%H:%M:%S.%fZ")
            last_time_seen_datetime = local_time_to_utc(last_time_seen_datetime)
            new_last_time_seen = last_time_seen_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            new_last_time_seen_object = obj
            new_last_time_seen_object['value'] = new_last_time_seen
    query = {'_id': ip_object['_id']}
    update_operators_part1 = {'$pull': {'objects': {'type': 'Last Time Received'}}}
    update_operators_part2 = {
        '$set': {
            'created': new_created_date,
            'modified': pendulum.now('UTC'),
            'status': 'Analyzed',
        },
        '$push': {'objects': new_last_time_seen_object}
    }
    ips.update_one(filter=query, update=update_operators_part1)
    ips.update_one(filter=query, update=update_operators_part2)
    number_of_ips += 1
duration = datetime.now() - start_time
print "Time to update IPs:", duration
print "Number of IPs:", number_of_ips


events = client.crits.events
event_objects = events.find(filter=in_progress_filter)
number_of_events = 0

start_time = datetime.now()
for event_object in event_objects:
    new_created_date = local_time_to_utc(event_object['created'])
    query = {'_id': event_object['_id']}
    update_operators = {
        '$set': {
            'created': new_created_date,
            'modified': pendulum.now('UTC'),
            'status': 'New'
        }
    }
    events.update_one(filter=query, update=update_operators)
    number_of_events += 1
duration = datetime.now() - start_time
print "Time to update Events:", duration
print "Number of Events:", number_of_events
