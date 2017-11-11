import pendulum
from UserStatisticsCollector import UserStatisticsCollector
from UserStatisticsReporter import UserStatisticsReporter


class UserStatisticsTester:

    def __init__(self):
        self.collector = UserStatisticsCollector()
        self.reporter = UserStatisticsReporter()

    def test_collector(self):
        today = pendulum.today('UTC')
        yesterday_start = today.subtract(days=1)
        yesterday_end = today.subtract(microseconds=1)
        for user in self.collector.find_users():
            username = user['username']
            submissions_counts = self.collector.count_submissions_from_user_within_duration(username, yesterday_start, yesterday_end)
            manual_submissions_counts = self.count_submissions_from_user(username, yesterday_start, yesterday_end)
            manual_ips_count = manual_submissions_counts['ips']
            manual_events_count = manual_submissions_counts['events']
            if submissions_counts['ips'] != manual_ips_count or submissions_counts['events'] != manual_events_count:
                print "Stats on User '" + username + "':"
                print "Number of IPs, method 1:", submissions_counts['ips']
                print "Number of IPs, method 2:", manual_ips_count
                print "Number of Events, method 1:", submissions_counts['events']
                print "Number of Events, method 2:", manual_events_count

    def count_submissions_from_user(self, username, duration_start, duration_end):
        query = {
            'created': {
                '$gte': duration_start,
                '$lte': duration_end
            }
        }
        ips_from_user = {}
        number_of_events_from_user = 0
        event_objects = self.collector.events.find(filter=query)
        for event_object in event_objects:
            for source in event_object['source']:
                for instance in source['instances']:
                    if instance['analyst'] == username:
                        number_of_events_from_user += 1
                        for relationship in event_object['relationships']:
                            ip_id = relationship['value']
                            ip_object = self.collector.ips.find_one(filter={'_id': ip_id})
                            ip_address = ip_object['ip']
                            if ip_address not in ips_from_user:
                                ips_from_user[ip_address] = True
        counts = {
            'ips': len(ips_from_user),
            'events': number_of_events_from_user
        }
        return counts

tester = UserStatisticsTester()
tester.test_collector()
