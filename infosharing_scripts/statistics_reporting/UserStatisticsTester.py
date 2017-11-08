from datetime import timedelta
from UserStatisticsCollector import UserStatisticsCollector
from UserStatisticsReporter import UserStatisticsReporter


class UserStatisticsTester:

    def __init__(self):
        self.collector = UserStatisticsCollector()
        self.reporter = UserStatisticsReporter()

    def test_collector(self):
        for user in self.collector.find_users():
            username = user['username']
            submissions_counts = self.collector.count_submissions_from_user_within_day(username)
            number_of_ips = self.count_ips_from_user(username, submissions_counts['time_collected'])
            number_of_events = self.count_events_from_user(username, submissions_counts['time_collected'])
            if number_of_ips != submissions_counts['ips'] or number_of_events != submissions_counts['events']:
                print "Stats on User '" + username + "':"
                print "Number of IPs, method 1:", submissions_counts['ips']
                print "Number of IPs, method 2:", number_of_ips
                print "Number of Events, method 1:", submissions_counts['events']
                print "Number of Events, method 2:", number_of_events

    def count_ips_from_user(self, username, time_collected):
        # TODO: Should I round up or down for the datetime I use to filter? Should I round at all?
        # TODO: Change day period back to 30 days when done testing
        start_period = time_collected - timedelta(days=120)
        query = {
            'created': {
                '$gte': start_period,
                '$lte': time_collected
            }
        }
        ips_from_user = {}
        event_objects = self.collector.events.find(filter=query)
        for event_object in event_objects:
            for source in event_object['source']:
                for instance in source['instances']:
                    if instance['analyst'] == username:
                        for relationship in event_object['relationships']:
                            ip_id = relationship['value']
                            ip_object = self.collector.ips.find_one(filter={'_id': ip_id})
                            ip_address = ip_object['ip']
                            if ip_address not in ips_from_user:
                                ips_from_user[ip_address] = True
                            break
        return len(ips_from_user)

    def count_events_from_user(self, username, time_collected):
        # TODO: Should I round up or down for the datetime I use to filter? Should I round at all?
        # TODO: Change day period back to 30 days when done testing
        start_period = time_collected - timedelta(days=120)
        query = {
            'created': {
                '$gte': start_period,
                '$lte': time_collected
            }
        }
        number_of_events_from_user = 0
        event_objects = self.collector.events.find(filter=query)
        for event_object in event_objects:
            for source in event_object['source']:
                for instance in source['instances']:
                    if instance['analyst'] == username:
                        number_of_events_from_user += 1
        return number_of_events_from_user

tester = UserStatisticsTester()
tester.test_collector()
