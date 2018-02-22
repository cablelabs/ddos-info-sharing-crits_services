from pymongo import MongoClient

client = MongoClient()
old_ips = client.old_crits_data.ips
old_events = client.old_crits_data.events

old_ips.delete_many({})
old_events.delete_many({})
