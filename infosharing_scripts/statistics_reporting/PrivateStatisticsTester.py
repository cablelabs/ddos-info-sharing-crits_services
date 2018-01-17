import pendulum
from PrivateStatisticsCollector import PrivateStatisticsCollector
from IPAddressChecker import IPAddressChecker


class PrivateStatisticsTester:

    def __init__(self):
        self.collector = PrivateStatisticsCollector()
        self.ip_address_checker = IPAddressChecker()

    def test_collector(self):
        today_utc = pendulum.today('UTC')
        print "Today (UTC):", today_utc
        number_events_top_asns_collector = self.collector.count_events_top_attacking_asns_multiple_reporters(today_utc)
        print number_events_top_asns_collector
        number_events_top_asns_manual = self.count_events_top_attacking_asns_multiple_reporters(today_utc)
        print number_events_top_asns_manual
        return

    def count_events_top_attacking_asns_multiple_reporters(self, end_time, number_of_asns=10):
        """
        Find the top attacking AS Numbers, and return the number of Events for these top attacking ASNs. This is
        done by taking each ASN and counting the number of Events corresponding to IP addresses whose ASN lookup
        information maps to that ASN. Only counts Events for IPs that have been reported by multiple sources.
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :param number_of_asns: The maximum number of ASNs to return.
        :type number_of_asns: int
        :return: array of 2-tuples whose type is (string, int), sorted on 2nd value in descending order
        """
        pipeline = [
            {'$match': {'created': {'$lte': end_time}}},
            {'$unwind': '$objects'},
            {
                '$match': {
                    'objects.type': 'Number of Reporters',
                    'objects.value': {'$gt': "1"}
                }
            }
        ]
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        ip_objects = self.collector.ips.aggregate(pipeline, collation=collation, allowDiskUse=True)
        asns_counts = {}
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if self.ip_address_checker.is_valid_ip(ip_address):
                number_of_events = 0
                for relationship in ip_object['relationships']:
                    event_id = relationship['value']
                    event_object = self.collector.events.find_one({'_id': event_id})
                    if event_object and event_object['created'] <= end_time:
                        number_of_events += 1
                full_ip_object = self.collector.ips.find_one(filter={'_id': ip_object['_id']})
                for obj in full_ip_object['objects']:
                    if obj['type'] == 'AS Number':
                        asn = obj['value']
                        if asn not in asns_counts:
                            asns_counts[asn] = number_of_events
                        else:
                            asns_counts[asn] += number_of_events
        return sorted(asns_counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_asns]

tester = PrivateStatisticsTester()
tester.test_collector()
