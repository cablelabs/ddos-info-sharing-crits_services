from datetime import datetime
from pymongo import MongoClient

sample_size = 10

client = MongoClient()
ips = client.crits.ips
# TODO: define "earliest" and "latest" for IP objects, and what field to extract.
earliest_ip_object = ips.find_one(sort=[('modified', 1)])
earliest_time = earliest_ip_object['modified']
latest_ip_object = ips.find_one(sort=[('modified', 1)])
latest_time = latest_ip_object['modified']

total_duration = latest_time - earliest_time
partial_duration = total_duration / sample_size
time_now_str = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
filename = 'data_file_'+time_now_str+'.txt'
data_file = open(filename, 'w')
for i in range(0, sample_size):
    next_sample_time = earliest_time + partial_duration * i
    query = {'modified': {'$gte': next_sample_time}}
    ip_object = ips.find_one(filter=query, sort=[('modified', 1)])
    # TODO: write data to file. Not sure how to write object data yet.
    data_file.write()
