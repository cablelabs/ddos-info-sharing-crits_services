from pymongo import MongoClient


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
        return

    def count_ips_by_status(self):
        counts = {}
        status_options = ['New', 'In Progress', 'Analyzed']
        for status in status_options:
            query = {'status': status}
            counts[status] = self.ips.count(filter=query)
        return counts

reporter = QuickStatsReporter()
reporter.run()
