# Set the status of every IP and Event to "In Progress".
from pymongo import MongoClient

client = MongoClient()
ips = client.crits.ips
events = client.crits.events
ips.update_many({}, {'$set': {'status': 'In Progress'}})
events.update_many({}, {'$set': {'status': 'In Progress'}})
