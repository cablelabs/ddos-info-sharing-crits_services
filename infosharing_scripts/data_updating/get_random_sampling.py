import csv
import random
from pymongo import MongoClient

sample_size = 10

client = MongoClient()
ips = client.crits.ips
events = client.crits.events
number_of_ips = ips.count()
number_of_events = events.count()
random_ip_indexes = random.sample(range(0, number_of_ips), sample_size)
random_event_indexes = random.sample(range(0, number_of_events), sample_size)

field_names = ['ID', 'IP address', 'created', 'Last Time Received']
with open('samples_before_update.csv', 'w') as sampling_file:
    samples_before_writer = csv.DictWriter(sampling_file, fieldnames=field_names)
    samples_before_writer.writeheader()
    for idx in random_ip_indexes:
        # How we sort before we skip is arbitrary, as log as we sort the same way each time to avoid picking the same
        # IP multiple times.
        ip_object = ips.find_one(skip=idx, sort=[('_id', 1)])
        next_row = {
            'ID': ip_object['_id'],
            'IP address': ip_object['ip'],
            'created': ip_object['created'],
            'Last Time Received': 'N/A'
        }
        for o in ip_object['objects']:
            if o['type'] == 'Last Time Received':
                next_row['Last Time Received'] = o['value']
                # Note: We expect only one value for 'Last Time Received' in our application.
                break
        samples_before_writer.writerow(next_row)
    for idx in random_event_indexes:
        event_object = events.find_one(skip=idx, sort=[('_id', 1)])
        next_row = {
            'ID': event_object['_id'],
            'IP address': 'Event',
            'created': event_object['created'],
            'Last Time Received': 'N/A'
        }
        samples_before_writer.writerow(next_row)
