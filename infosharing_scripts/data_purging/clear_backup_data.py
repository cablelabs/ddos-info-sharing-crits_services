# NOTE: This script should only be used in testing to clear the data in the "old_crits_data".
# It is not meant to be used in production.

from pymongo import MongoClient

client = MongoClient()
old_ips = client.old_crits_data.ips
old_events = client.old_crits_data.events

old_ips.delete_many({})
old_events.delete_many({})
