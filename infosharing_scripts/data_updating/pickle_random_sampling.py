import pickle
import random
from pymongo import MongoClient

sample_size = 1000

client = MongoClient()
ips = client.crits.ips
events = client.crits.events
number_of_ips = ips.count()
number_of_events = events.count()
random_ip_indexes = random.sample(range(0, number_of_ips), sample_size)
random_event_indexes = random.sample(range(0, number_of_events), sample_size)

with open('samples_before.pickle', 'wb') as samples_before_file:
    for idx in random_ip_indexes:
        # How we sort before we skip is arbitrary, as log as we sort the same way each time to avoid picking the same
        # IP multiple times.
        ip_object = ips.find_one(skip=idx, sort=[('_id', 1)])
        pickle.dump(ip_object, samples_before_file, protocol=pickle.HIGHEST_PROTOCOL)

    for idx in random_event_indexes:
        event_object = events.find_one(skip=idx, sort=[('_id', 1)])
        pickle.dump(event_object, samples_before_file, protocol=pickle.HIGHEST_PROTOCOL)
