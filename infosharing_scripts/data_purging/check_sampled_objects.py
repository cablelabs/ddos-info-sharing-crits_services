from bson import json_util
import json
import sys
import pendulum
import pytz
from pymongo import MongoClient


def is_relationships_equal(r1, r2):
    return r1['rel_confidence'] == r2['rel_confidence'] and \
           r1['relationship'] == r2['relationship'] and \
           r1['relationship_date'] == r2['relationship_date'] and \
           r1['value'] == r2['value'] and \
           r1['date'] == r2['date'] and \
           r1['type'] == r2['type'] and \
           r1['analyst'] == r2['analyst'] and \
           r1['rel_reason'] == r2['rel_reason']


client = MongoClient()
ips = client.crits.ips
events = client.crits.events
config_filename = '/data/configs/duration_config.json'
with open(config_filename, 'r') as config_file:
    configs = json.load(config_file)
    months = configs['months']
    days = configs['days']
    today_datetime = pendulum.today('UTC')
    earliest_datetime = today_datetime.subtract(months=months, days=days)
if earliest_datetime is None:
    sys.exit("Error: earliest_datetime not defined.")
with open('samples_before_update.json', 'r') as samples_file:
    saved_data = json.load(samples_file, object_hook=json_util.object_hook)


# Note: Might be able to calculate this value faster with aggregation query.
number_of_ips_before_date = 0
ip_objects = ips.find()
for ip_object in ip_objects:
    for obj in ip_object['objects']:
        if obj['type'] == "Last Time Received":
            last_time_received_str = obj['value']
            last_time_received_datetime = pendulum.from_format(last_time_received_str, '%Y-%m-%dT%H:%M:%S.%fZ')
            if last_time_received_datetime < earliest_datetime:
                number_of_ips_before_date += 1
print "Number of IPs before date:", number_of_ips_before_date
number_of_ips = ips.count()
print "Number of IPs after date:", number_of_ips - number_of_ips_before_date
for saved_ip_object in saved_data['ips']:
    ip_object = ips.find_one(filter={'_id': saved_ip_object['_id']})
    if ip_object is None:
        # Confirm that all related Events no longer exist, and thus it was correct to remove the IP.
        for relationship in saved_ip_object['relationships']:
            event_id = relationship['value']
            if events.count(filter={'_id': event_id}) > 0:
                print "Error: Event still exists!"
    else:
        if len(saved_ip_object['relationships']) != len(ip_object['relationships']) and \
                        ip_object['status'] != "In Progress":
            print "Error: IP object not 'In Progress', even though some (but not all) Events have been deleted!"
        for saved_relationship in saved_ip_object['relationships']:
            event_id = saved_relationship['value']
            if events.count(filter={'_id': event_id}) > 0:
                # Confirm that relationship still exists because Event exists.
                found_relationship = False
                for relationship in ip_object['relationships']:
                    relationship['relationship_date'] = relationship['relationship_date'].replace(tzinfo=pytz.utc)
                    relationship['date'] = relationship['date'].replace(tzinfo=pytz.utc)
                    if is_relationships_equal(saved_relationship, relationship):
                        found_relationship = True
                        break
                if not found_relationship:
                    print "Error: Relationship to Event doesn't exist when it should!"
            else:
                # Confirm that relationship is no longer in IP object because Event no longer exists.
                for relationship in ip_object['relationships']:
                    relationship['relationship_date'] = relationship['relationship_date'].replace(tzinfo=pytz.utc)
                    relationship['date'] = relationship['date'].replace(tzinfo=pytz.utc)
                    if is_relationships_equal(saved_relationship, relationship):
                        print "Error: Relationship to Event still exists when it shouldn't!"
                        break


created_before_query = {'created': {'$lt': earliest_datetime}}
number_of_events_before_date = events.count(filter=created_before_query)
print "Number of Events before date:", number_of_events_before_date
created_after_query = {'created': {'$gte': earliest_datetime}}
number_of_events_after_date = events.count(filter=created_after_query)
print "Number of Events after date:", number_of_events_after_date
for saved_event in saved_data['events']:
    created = saved_event['created']
    event_object = events.find_one(filter={'_id': saved_event['_id']})
    if event_object is None and created >= earliest_datetime:
        print "Error: Event doesn't exist when created date within range!"
    elif event_object is not None and created < earliest_datetime:
        print "Error: Event still exists when created date outside range!"
