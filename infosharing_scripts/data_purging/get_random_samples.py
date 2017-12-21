from bson import json_util
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


sample_size = 1000
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
data_to_save = {'ips': [], 'events': []}


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
number_of_ips_after_date = number_of_ips - number_of_ips_before_date
print "Number of IPs after date:", number_of_ips_after_date
random_ip_after_indexes = random_sample(range(0, number_of_ips_after_date), sample_size)
ip_objects = ips.find(sort=[('modified', -1)])
current_ips_before_index = 0
current_ips_after_index = 0
for ip_object in ip_objects:
    for obj in ip_object['objects']:
        if obj['type'] == "Last Time Received":
            last_time_received_str = obj['value']
            last_time_received_datetime = pendulum.from_format(last_time_received_str, '%Y-%m-%dT%H:%M:%S.%fZ')
            simplified_ip_object = {
                '_id': ip_object['_id'],
                'last_time_received': last_time_received_str,
                'relationships': ip_object['relationships']
            }
            if last_time_received_datetime < earliest_datetime:
                if current_ips_before_index in random_ip_before_indexes:
                    data_to_save['ips'].append(simplified_ip_object)
                current_ips_before_index += 1
            else:
                if current_ips_after_index in random_ip_after_indexes:
                    data_to_save['ips'].append(simplified_ip_object)
                current_ips_after_index += 1
            break


created_before_query = {'created': {'$lt': earliest_datetime}}
number_of_events_before_date = events.count(filter=created_before_query)
print "Number of Events before date:", number_of_events_before_date
before_aggregation_stages = [
    {'$match': created_before_query},
    {'$sample': {'size': sample_size}}
]
random_events_before = events.aggregate(before_aggregation_stages)
for event in random_events_before:
    simplified_event = {
        '_id': event['_id'],
        'created': event['created']
    }
    data_to_save['events'].append(simplified_event)


created_after_query = {'created': {'$gte': earliest_datetime}}
number_of_events_after_date = events.count(filter=created_after_query)
print "Number of Events after date:", number_of_events_after_date
after_aggregation_stages = [
    {'$match': created_after_query},
    {'$sample': {'size': sample_size}}
]
random_events_after = events.aggregate(after_aggregation_stages)
for event in random_events_after:
    simplified_event = {
        '_id': event['_id'],
        'created': event['created']
    }
    data_to_save['events'].append(simplified_event)


with open('samples_before_update.json', 'w') as sampling_file:
    json.dump(data_to_save, sampling_file, default=json_util.default)
