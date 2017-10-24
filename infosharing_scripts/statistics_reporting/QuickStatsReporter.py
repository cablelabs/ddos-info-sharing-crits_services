from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING


class QuickStatsReporter:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users

    def run(self):
        # Print the number of IPs of each particular status, and total number of IPs and Events.
        print "Total # of IPs: " + str(self.ips.count())
        print "Total # of Events: " + str(self.events.count())
        print "Status of IPs:"
        ip_status_count = self.count_ips_by_status()
        for key, value in ip_status_count.iteritems():
            print key + ":" + str(value)
        time_now = datetime.now()
        one_month_ago = time_now - timedelta(days=30)
        print "Total # of IPs beyond 30 days:", self.count_old_ips(one_month_ago)
        print "Total # of IPs within 30 days:", self.count_new_ips(one_month_ago)
        average_submission_rate = self.calculate_average_submission_rate()
        print "Average Submission Rate: " + str(average_submission_rate) + " events/day"
        return

    def count_ips_by_status(self):
        counts = {}
        status_options = ['New', 'In Progress', 'Analyzed']
        for status in status_options:
            query = {'status': status}
            counts[status] = self.ips.count(filter=query)
        return counts

    def calculate_average_submission_rate(self):
        # Note: At the moment, this calculates the average rate among all days before today.
        first_event = self.events.find_one(sort=[('created', ASCENDING)])
        first_date = first_event['created']
        earliest_date = datetime(year=first_date.year, month=first_date.month, day=first_date.day)
        yesterday = datetime.today() - timedelta(days=1)
        latest_date = datetime(year=yesterday.year, month=yesterday.month, day=yesterday.day)
        difference = latest_date - earliest_date
        number_of_days = difference.days
        query = {
            'created': {
                '$gte': earliest_date,
                '$lt': latest_date
            }
        }
        number_of_events = self.events.count(filter=query)
        return number_of_events / float(number_of_days)

    def count_old_ips(self, timestamp):
        query = {'modified': {'$lt': timestamp}}
        return self.ips.count(filter=query)

    def count_new_ips(self, timestamp):
        query = {'modified': {'$gte': timestamp}}
        return self.ips.count(filter=query)

reporter = QuickStatsReporter()
reporter.run()
