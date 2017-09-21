from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from pymongo import MongoClient, DESCENDING


class MongoDBFunctionsWrapper:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
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

    def count_sources(self):
        return self.source_access.count()

    def count_users(self):
        return self.users.count()

    def count_ips_by_status(self):
        counts = {}
        status_options = ['New', 'In Progress', 'Analyzed']
        for status in status_options:
            query = {'status': status}
            counts[status] = self.ips.count(filter=query)
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

    def count_submissions_by_user(self):
        counts = {}
        current_user_counts = 0
        return counts

    def count_ips_by_owning_source(self):
        counts = {}
        source_names = self.source_access.find(projection={'name': 1})
        for entry in source_names:
            source_name = entry['name']
            count = self.ips.count({'releasability.name': source_name})
            counts[source_name] = count
        return counts
