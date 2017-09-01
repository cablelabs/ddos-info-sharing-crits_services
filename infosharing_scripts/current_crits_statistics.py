from datetime import datetime
from pymongo import MongoClient

client = pymongo.MongoClient()
output_file = open('current_statistics_'+datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%LZ')+'.txt', 'w')

# Task 1: Number of IPs per source
source = client.crits.source_access
sources = source.find()
source_names = []
for src in sources:
    source_names.append(src['name'])

ips = client.crits.ips
for name in source_names:
    query = {

    }
    count = ips.count(query)
    output_file.write("'Number of unique IPs received from '" + name + "':" + str(count))


output_file.close()