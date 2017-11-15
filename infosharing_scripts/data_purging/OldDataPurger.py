import csv
import pendulum
from multiprocessing import Pool
from pymongo import MongoClient


def retrieve_ith_ip_address(i):
    client = MongoClient()
    ips = client.crits.ips
    ip_object = ips.find_one(skip=i, sort=[('modified', 1)])
    return ip_object['ip']


def remove_ip_object(ip_address):
    client = MongoClient()
    ips = client.crits.ips
    events = client.crits.events
    ip_object = ips.find_one(filter={'ip': ip_address})
    try:
        ip_id = ip_object['_id']
        ips.delete_one({'_id': ip_id})
        for relationship in ip_object['relationships']:
            if relationship['type'] == 'Event':
                event_id = relationship['value']
                events.delete_one({'_id': event_id})
    except TypeError as e:
        print e.message


class OldDataPurger:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users

    def delete_old_ips(self, months=0, days=0):
        # TODO: Later on, delete old entries based on 'Last Time Received', NOT the time it was modified.
        # Aggregation query in future version: in IPs collection, unwind objects, filter on type "Last Time Received"...
        number_of_ips_before = self.ips.count()
        time_now = pendulum.now()
        earliest_date = time_now.subtract(months=months, days=days)
        query = {'modified': {'$lt': earliest_date}}
        self.ips.delete_many(filter=query)
        print "IPs Deleted:", number_of_ips_before - self.ips.count()
        return

    def delete_ips(self):
        """
        Delete IPs until there are about 10,000 in the database.
        :return:
        """
        number_of_ips = self.ips.count()
        pool = Pool(10)
        increment = number_of_ips / 10000
        ip_addresses = pool.map(retrieve_ith_ip_address, range(0, number_of_ips, increment))
        #pool.map(remove_ip_object, ip_addresses)
        pool.close()
        self.ips.delete_many(filter={'ip': {'$nin': ip_addresses}})
        print "IPs Deleted:", number_of_ips - self.ips.count()

    def remove_events_with_no_ip(self):
        event_objects = self.events.find()
        number_of_events = self.events.count()
        for event_object in event_objects:
            for relationship in event_object['relationships']:
                ip_id = relationship['value']
                ip_object = self.ips.find_one(filter={'_id': ip_id})
                if ip_object is None:
                    event_id = event_object['_id']
                    self.events.delete_one(filter={'_id': event_id})
        print "Events Deleted:", number_of_events - self.events.count()
