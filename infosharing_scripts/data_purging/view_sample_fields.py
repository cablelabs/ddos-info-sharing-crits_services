import csv
import json
import sys
import pendulum
from pymongo import MongoClient
from bson.objectid import ObjectId

client = MongoClient()
ips = client.crits.ips
events = client.crits.events

config_filename = 'duration_config.json'
with open(config_filename, 'r') as config_file:
    configs = json.load(config_file)
    months = configs['months']
    days = configs['days']
    today_datetime = pendulum.today('UTC')
    earliest_datetime = today_datetime.subtract(months=months, days=days)
if earliest_datetime is None:
    sys.exit("Error: earliest_datetime not defined.")

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
print "Number of other IPs:", number_of_ips - number_of_ips_before_date

before_query = {'created': {'$lt': earliest_datetime}}
number_of_events_before_date = events.count(filter=before_query)
print "Number of Events before date:", number_of_events_before_date
number_of_events = events.count()
print "Number of other Events:", number_of_events - number_of_events_before_date

field_names = ['ID', 'IP address', 'created', 'Last Time Received']
with open('samples_before_update.csv', 'r') as samples_before_file:
    samples_before_reader = csv.DictReader(samples_before_file)
    with open('samples_after_update.csv', 'w') as samples_after_file:
        samples_after_writer = csv.DictWriter(samples_after_file, fieldnames=field_names)
        samples_after_writer.writeheader()
        for row in samples_before_reader:
            object_id = ObjectId(row['ID'])
            ip_address = row['IP address']
            if ip_address != 'Event':
                ip_object = ips.find_one(filter={'_id': object_id})
                if ip_object is not None:
                    next_row = {
                        'ID': object_id,
                        'IP address': ip_object['ip'],
                        'created': ip_object['created'],
                        'Last Time Received': None,
                    }
                    for o in ip_object['objects']:
                        if o['type'] == 'Last Time Received':
                            # We expect only one value for 'Last Time Received'. Make a note if there's multiple values.
                            if next_row['Last Time Received']:
                                next_row['Last Time Received'] = '(multiple values)'
                            else:
                                next_row['Last Time Received'] = o['value']
                    samples_after_writer.writerow(next_row)
                else:
                    next_row = {
                        'ID': object_id,
                        'IP address': 'N/A',
                        'created': 'N/A',
                        'Last Time Received': 'N/A',
                    }
                    samples_after_writer.writerow(next_row)
            else:
                event_object = events.find_one(filter={'_id': object_id})
                if event_object is not None:
                    next_row = {
                        'ID': object_id,
                        'IP address': 'Event',
                        'created': event_object['created'],
                        'Last Time Received': 'N/A',
                    }
                    samples_after_writer.writerow(next_row)
                else:
                    next_row = {
                        'ID': object_id,
                        'IP address': 'N/A',
                        'created': 'N/A',
                        'Last Time Received': 'N/A',
                    }
                    samples_after_writer.writerow(next_row)
