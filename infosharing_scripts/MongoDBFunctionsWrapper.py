from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from pymongo import MongoClient, DESCENDING


class MongoDBFunctionsWrapper:

    # Ideas for functions:
    # - The number of IPs or Events submitted in a given time frame (day/week/month).
    # - The number of IPs or Events submitted each month.
    # - For these two ideas, IPs can mean any IP submitted, or only new IPs submitted, or only IPs for a given ISP/user.
    # - Not a collector function: A function to re-analyze a specific set of IP addresses
    # (i.e. when you see just a few that are off, re-analyze and see if they get fixed)

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events

    ### Find Functions ###

    # - The latest date of any Analyzed IP address. This function isn't quite what I want. I want the latest date that an
    # IP which is currently analyzed was submitted to the system. Looking at the 'created' date may not be enough because
    #
    def find_latest_date_ip_analyzed(self):
        """
        The RFC 3339 formatted date of the the latest time that a currently Analyzed IP address was created.
        :return: str
        """
        ip_object = self.ips.find_one(filter={'status': 'Analyzed'}, sort=[('created', DESCENDING)])
        return str(ip_object['created'])

    ### Count Functions ###

    def count_ips_by_status(self):
        counts = {}
        status_options = ['New', 'In Progress', 'Analyzed']
        for status in status_options:
            query = {'status': status}
            counts[status] = self.ips.count(filter=query)
        return counts

    def count_old_and_new_ips(self, days_ago=30):
        """
        Return counts of the number of IPs that are considered "old" or "new".
        :param days_ago: Maximum number of days ago from today until an IP is considered 'old'.
        :type days_ago: int
        :return: dict
        """
        counts = {}
        one_month_ago = datetime.today() - timedelta(days=days_ago)
        old_ips_query = {
            'created': {
                '$lt': one_month_ago
            }
        }
        old_ips_key = 'IPs older than ' + str(days_ago) + ' days'
        counts[old_ips_key] = self.ips.count(filter=old_ips_query)
        new_ips_query = {
            'created': {
                '$gte': one_month_ago
            }
        }
        new_ips_key = 'IPs within ' + str(days_ago) + ' days'
        counts[new_ips_key] = self.ips.count(filter=new_ips_query)
        return counts

    def count_old_and_new_events(self, days_ago=30):
        """
        Return counts of the number of Events that are considered "old" or "new".
        :param days_ago: Maximum number of days ago from today until an Event is considered 'old'.
        :type days_ago: int
        :return: dict
        """
        counts = {}
        one_month_ago = datetime.today() - timedelta(days=days_ago)
        old_events_query = {
            'created': {
                '$lt': one_month_ago
            }
        }
        old_events_key = 'Events older than ' + str(days_ago) + ' days'
        counts[old_events_key] = self.events.count(filter=old_events_query)
        new_events_query = {
            'created': {
                '$gte': one_month_ago
            }
        }
        new_events_key = 'Events within ' + str(days_ago) + ' days'
        counts[new_events_key] = self.events.count(filter=new_events_query)
        return counts

    def count_unique_ip_per_month(self):
        counts = {}
        start_month = datetime(year=2017, month=6, day=1)
        current_month = start_month
        today = datetime.today()
        while current_month < today:
            next_month = current_month + relativedelta(months=1)
            query = {
                'created': {
                    '$gte': current_month,
                    '$lt': next_month
                }
            }
            current_month_str = current_month.strftime("%Y-%m")
            counts[current_month_str] = self.ips.count(filter=query)
            current_month = next_month
        return counts

    # TODO: should this mean IPs 'created' or 'modified' each month? I'm guessing modified, not unique IPs
    def count_submissions_per_month(self):
        # Note: In a given month, the number of IPs and Events is unequal if and only if users submit to the same IP
        # multiple times, resulting in more events but not more IPs. So IPs should always be less.
        counts = {}
        start_month = datetime(year=2017, month=6, day=1)
        current_month = start_month
        today = datetime.today()
        while current_month < today:
            next_month = current_month + relativedelta(months=1)
            current_month_counts = {}
            # TODO: Counting IPs in the desired manner may require using aggregation.
            current_month_counts['ips'] = 0 #self.ips.count()
            query = {
                'created': {
                    '$gte': current_month,
                    '$lt': next_month
                }
            }
            current_month_counts['events'] = self.events.count(query)
            current_month_str = current_month.strftime("%Y-%m")
            counts[current_month_str] = current_month_counts
            current_month = next_month
        return counts

    ### Remove Functions ###

    def remove_old_events(self):
        one_month_ago = datetime.today() - timedelta(days=30)
        # TODO: Use time event was created, or the attack start or stop time?
        query = {
            'created': {
                '$lt': one_month_ago
            }
        }
        self.events.delete_many(filter=query)

    def remove_ips_with_no_events(self):
        ip_objects = self.ips.find()
        ids_of_ips_to_remove = []
        for ip_object in ip_objects:
            has_event = False
            for relationship in ip_object['relationships']:
                if relationship['rel_type'] == 'Event':
                    has_event = True
                    break
            if not has_event:
                ids_of_ips_to_remove.append(ip_object['_id'])
        query = {
            '_id': {
                '$in': ids_of_ips_to_remove
            }
        }
        self.ips.delete_many(filter=query)

    ### Update Functions ###

    # TODO: test methods of filtering relationships on events. One just iterates over relationships field.
    # Other method does aggregation. There might also be a Python function that could filter the relationships array.

    # version 1: just iterate, don't try anymore MongoDB tricks I don't know off-hand
    def update_event_relationships_all_ips(self):
        ip_objects = self.ips.find()
        for ip_object in ip_objects:
            ids_of_relationships_to_remove = []
            for relationship in ip_object['relationships']:
                if relationship['rel_type'] == 'Event':
                    event_id = relationship['object_id']
                    event = self.events.find_one({'_id': event_id})
                    if not event:
                        ids_of_relationships_to_remove.append(relationship['_id'])
            query = {'_id': ip_object['_id']}
            update = {
                '$pull': {
                    'relationships.id': {
                        '$in': ids_of_relationships_to_remove
                    }
                }
            }
            self.ips.update_many(filter=query, update=update)
