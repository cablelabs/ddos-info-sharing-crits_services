import csv
from pymongo import MongoClient
from bson.objectid import ObjectId

client = MongoClient()
ips = client.crits.ips
events = client.crits.events


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
                samples_after_writer.writerow(next_row)
            else:
                event_object = events.find_one(filter={'_id': object_id})
                next_row = {
                    'ID': event_object['_id'],
                    'IP address': 'Event',
                    'created': event_object['created'],
                    'Last Time Received': 'N/A'
                }
                samples_after_writer.writerow(next_row)
