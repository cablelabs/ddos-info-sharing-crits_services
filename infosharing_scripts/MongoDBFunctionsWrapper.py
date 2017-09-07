from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from pymongo import MongoClient, DESCENDING


class MongoDBFunctionsWrapper:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.users = client.crits.users

    ### Find Functions ###

    def find_ips_ids(self):
        cursor = self.ips.find(projection={})
        ips_ids = []
        for entry in cursor:
            ips_ids.append(entry['_id'])
        return ips_ids

    def find_new_ips_ids(self):
        one_month_ago = datetime.today() - relativedelta(days=70)
        # Filter based on 'modified' date because the "old" IPs are those whose latest Event is still considered "old",
        # and IPs with new Events may have been created long before their latest Event was added.
        query = {
            'modified': {
                '$gte': one_month_ago
            }
        }
        cursor = self.ips.find(filter=query, projection={})
        ips_ids = []
        for entry in cursor:
            ips_ids.append(entry['_id'])
        return ips_ids

    def find_events_ids(self):
        cursor = self.events.find(projection={})
        events_ids = []
        for entry in cursor:
            events_ids.append(entry['_id'])
        return events_ids

    def find_new_events_ids(self):
        one_month_ago = datetime.today() - relativedelta(days=70)
        query = {
            'created': {
                '$gte': one_month_ago
            }
        }
        cursor = self.events.find(filter=query, projection={})
        events_ids = []
        for entry in cursor:
            events_ids.append(entry['_id'])
        return events_ids

    def find_ips_with_invalid_relationships(self):
        """
        Find all IPs with one or more invalid relationships.
        :return: dict
        """
        # TODO: Figure out how to make this faster. It runs very slow now when there are many IPs.
        ip_objects = self.ips.find()
        ids_of_bad_ips = []
        for ip_object in ip_objects:
            for relationship in ip_object['relationships']:
                if relationship['type'] == 'Event':
                    event_id = relationship['value']
                    event = self.events.find_one({'_id': event_id})
                    if not event:
                        ids_of_bad_ips.append(ip_object['_id'])
                        break
        query = {
            '_id': {
                '$in': ids_of_bad_ips
            }
        }
        projection = {
            'ip': 1,
            'relationships': 1
        }
        bad_ips = self.ips.find(filter=query, projection=projection)
        return bad_ips

    ### Count Functions ###

    def count_ips(self):
        return self.ips.count()

    def count_events(self):
        return self.events.count()

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
        # Filter based on 'modified' date because the "old" IPs are those whose latest Event is still considered "old",
        # and IPs with new Events may have been created long before their latest Event was added.
        old_ips_query = {
            'modified': {
                '$lt': one_month_ago
            }
        }
        old_ips_key = 'IPs older than ' + str(days_ago) + ' days'
        counts[old_ips_key] = self.ips.count(filter=old_ips_query)
        new_ips_query = {
            'modified': {
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
        # TODO: Use time event was created, or the attack start or stop time?
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

    def count_unique_ips_per_month(self):
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

    def count_submissions_per_period(self, period='day'):
        """
        Count the number of IPs and Events submitted within the specified division of periods.

        :param period: The type of period into which the counts should be divided.
        :type period: str, one of 'day' or 'month'
        :return: dict
        :raise ValueError: 'period' parameter not a valid period to iterate across.
        """
        counts = {}
        start_period = datetime(year=2017, month=6, day=1)
        current_period = start_period
        today = datetime.today()
        if period == 'day':
            period_delta = relativedelta(days=1)
            format_string = "%m/%d/%Y"
        elif period == 'month':
            period_delta = relativedelta(months=1)
            format_string = "%m-%Y"
        else:
            raise ValueError("Invalid input for parameter 'period'.")
        while current_period < today:
            next_period = current_period + period_delta
            current_period_counts = {}
            ips_query = {
                'relationships': {
                    '$elemMatch': {
                        'date': {
                            '$gte': current_period,
                            '$lt': next_period
                        }
                    }
                }
            }
            current_period_counts['ips'] = self.ips.count(ips_query)
            events_query = {
                'created': {
                    '$gte': current_period,
                    '$lt': next_period
                }
            }
            current_period_counts['events'] = self.events.count(events_query)
            current_period_str = current_period.strftime(format_string)
            counts[current_period_str] = current_period_counts
            current_period = next_period
        return counts

    #TODO: Think if this is best way to count what I want. Are my assumptions valid?
    #TODO: How do I prevent overlap in IPs when counting? Do I want to prevent overlap?
    #TODO: possibly create another function that counts number of events they submitted.
    def count_ips_by_user(self):
        counts = {}
        for user in self.users.find():
            username = user['username']
            count = self.ips.count({'source.instances.analyst': username})
            counts[username] = count
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
                if relationship['type'] == 'Event':
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
    # Another method does aggregation. There might also be a Python function that could filter the relationships array.

    # version 1: just iterate, don't try anymore MongoDB tricks I don't know off-hand
    def update_event_relationships_all_ips(self):
        ip_objects = self.ips.find()
        for ip_object in ip_objects:
            ids_of_relationships_to_remove = []
            for relationship in ip_object['relationships']:
                if relationship['type'] == 'Event':
                    event_id = relationship['value']
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
