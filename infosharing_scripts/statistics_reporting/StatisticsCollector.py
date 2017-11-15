from pymongo import MongoClient


class StatisticsCollector:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users

    def find_one_user(self, username):
        return self.users.find_one({'username': username})

    def find_users(self):
        return self.users.find()
