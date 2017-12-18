import csv
import json
import random
import sys
import pendulum
from pymongo import MongoClient


def random_sample(population, k):
    # This is the same as random.sample(population, k) when len(population) >= k, but simply returns the whole
    # population if len(population) < k
    try:
        return random.sample(population, k)
    except ValueError:
        return population

sample_size = 5
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
random_ip_before_indexes = random_sample(range(0, number_of_ips_before_date), sample_size)
number_of_ips = ips.count()
print "Number of other IPs:", number_of_ips - number_of_ips_before_date
random_ip_after_indexes = random_sample(range(number_of_ips_before_date, number_of_ips), sample_size)

before_query = {'created': {'$lt': earliest_datetime}}
number_of_events_before_date = events.count(filter=before_query)
print "Number of Events before date:", number_of_events_before_date
random_events_before_indexes = random_sample(range(0, number_of_events_before_date), sample_size)
number_of_events = events.count()
print "Number of other Events:", number_of_events - number_of_events_before_date
random_events_after_indexes = random_sample(range(number_of_events_before_date, number_of_events), sample_size)

field_names = ['ID', 'IP address', 'created', 'Last Time Received']
with open('samples_before_update.csv', 'w') as sampling_file:
    samples_before_writer = csv.DictWriter(sampling_file, fieldnames=field_names)
    samples_before_writer.writeheader()
    ip_objects = ips.find(sort=[('modified', -1)])
    current_ips_before_index = 0
    current_ips_after_index = 0
    for ip_object in ip_objects:
        for obj in ip_object['objects']:
            if obj['type'] == "Last Time Received":
                last_time_received_str = obj['value']
                last_time_received_datetime = pendulum.from_format(last_time_received_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                if last_time_received_datetime < earliest_datetime:
                    if current_ips_before_index in random_events_before_indexes:
                        next_row = {
                            'ID': ip_object['_id'],
                            'IP address': ip_object['ip'],
                            'created': ip_object['created'],
                            'Last Time Received': last_time_received_str
                        }
                        samples_before_writer.writerow(next_row)
                    current_ips_before_index += 1
                else:
                    if current_ips_after_index in random_events_after_indexes:
                        next_row = {
                            'ID': ip_object['_id'],
                            'IP address': ip_object['ip'],
                            'created': ip_object['created'],
                            'Last Time Received': last_time_received_str
                        }
                        samples_before_writer.writerow(next_row)
                    current_ips_after_index += 1
                break
    for idx in random_events_before_indexes:
        # TODO: figure out if find_one skips before it sorts, or vice-versa
        event_object = events.find_one(skip=idx, sort=[('created', -1)])
        next_row = {
            'ID': event_object['_id'],
            'IP address': 'Event',
            'created': event_object['created'],
            'Last Time Received': 'N/A'
        }
        samples_before_writer.writerow(next_row)
    for idx in random_events_after_indexes:
        event_object = events.find_one(skip=idx, sort=[('created', -1)])
        next_row = {
            'ID': event_object['_id'],
            'IP address': 'Event',
            'created': event_object['created'],
            'Last Time Received': 'N/A'
        }
        samples_before_writer.writerow(next_row)
