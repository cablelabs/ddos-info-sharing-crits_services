from datetime import datetime
import pendulum
from GlobalStatisticsCollector import GlobalStatisticsCollector
from IPAddressChecker import IPAddressChecker


class GlobalStatisticsTester:

    def __init__(self):
        self.collector = GlobalStatisticsCollector()
        self.ip_address_checker = IPAddressChecker()

    def test_collector(self):
        today_utc = pendulum.today('UTC')
        print "Today (UTC):", today_utc

        # Note to self: Confirm total number of IPs and Events by simply running count queries in MongoDB shell.

        number_submissions_multiple_reporters_collector = self.collector.count_submissions_multiple_reporters(today_utc)
        number_ips_multiple_reporters_collector = number_submissions_multiple_reporters_collector['ips']
        print "Collector:", number_ips_multiple_reporters_collector
        start_time = datetime.now()
        number_ips_multiple_reporters_manual = self.count_ips_multiple_reporters(today_utc)
        duration = datetime.now() - start_time
        print "Manual:", number_ips_multiple_reporters_manual
        print "Duration to count IPs, multiple reporters, manual:", duration

        number_events_multiple_reporters_collector = number_submissions_multiple_reporters_collector['events']
        print "Collector:", number_events_multiple_reporters_collector
        start_time = datetime.now()
        number_events_multiple_reporters_manual = self.count_events_multiple_reporters(today_utc)
        duration = datetime.now() - start_time
        print "Manual:", number_events_multiple_reporters_manual
        print "Duration to count Events, multiple reporters, manual:", duration

        number_events_top_attack_types_collector = self.collector.count_events_top_attack_types_multiple_reporters(today_utc)
        print number_events_top_attack_types_collector
        number_events_top_attack_types_manual = self.count_events_top_attack_types_multiple_reporters(today_utc)
        print number_events_top_attack_types_manual

        number_events_top_attacking_countries_collector = self.collector.count_events_top_attacking_countries_multiple_reporters(today_utc)
        print number_events_top_attacking_countries_collector
        number_events_top_attacking_countries_manual = self.count_events_top_attacking_countries_multiple_reporters(today_utc)
        print number_events_top_attacking_countries_manual
        return

    def count_ips_multiple_reporters(self, end_time):
        """
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :return:
        """
        ip_objects = self.collector.find_ips()
        count = 0
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if ip_object['created'] <= end_time:
                if self.ip_address_checker.is_valid_ip(ip_address):
                    for obj in ip_object['objects']:
                        if obj['type'] == 'Number of Reporters':
                            if int(obj['value']) > 1:
                                count += 1
                            break
        return count

    def count_events_multiple_reporters(self, end_time):
        """
        Count the number of Events corresponding to IP addresses that have been reported by multiple sources.
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :return: int
        """
        ip_objects = self.collector.find_ips()
        count = 0
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if ip_object['created'] <= end_time:
                if self.ip_address_checker.is_valid_ip(ip_address):
                    for obj in ip_object['objects']:
                        if obj['type'] == 'Number of Reporters':
                            if int(obj['value']) > 1:
                                for relationship in ip_object['relationships']:
                                    event_id = relationship['value']
                                    event_object = self.collector.events.find_one({'_id': event_id})
                                    if event_object and event_object['created'] <= end_time:
                                        count += 1
                            break
        return count

    def count_events_top_attack_types_multiple_reporters(self, end_time, number_of_attack_types=10):
        """
        Find the top attack types based on number of events with a given attack type and are for IPs with multiple
        reporters. Return the number of events for the top attack types.
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :param number_of_attack_types: The maximum number of attack types to return.
        :type number_of_attack_types: int
        :return: array of 2-tuples whose type is (string, int)
        """
        ip_objects = self.collector.find_ips()
        attack_type_counts = {}
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if ip_object['created'] <= end_time:
                if self.ip_address_checker.is_valid_ip(ip_address):
                    for obj in ip_object['objects']:
                        if obj['type'] == 'Number of Reporters':
                            if int(obj['value']) > 1:
                                relationships = ip_object['relationships']
                                for relationship in relationships:
                                    event_id = relationship['value']
                                    event_object = self.collector.events.find_one({'_id': event_id})
                                    if event_object and event_object['created'] <= end_time:
                                        for obj in event_object['objects']:
                                            if obj['type'] == 'Attack Type':
                                                attack_type = obj['value']
                                                if attack_type not in attack_type_counts:
                                                    attack_type_counts[attack_type] = 1
                                                else:
                                                    attack_type_counts[attack_type] += 1
                            break
        return sorted(attack_type_counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_attack_types]

    def count_events_top_attacking_countries_multiple_reporters(self, end_time, number_of_countries=10):
        """
        For each country, count the number of events corresponding to IP addresses whose geoIP information maps to that
        country and has been reported by multiple sources. Then, return only the countries with the highest counts
        (along with their counts).
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :param number_of_countries: The maximum number of countries to return.
        :type number_of_countries: int
        :return: array of 2-tuples whose type is (string, int)
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
        countries_counts = {}
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
                    if obj['type'] == 'Country':
                        country = obj['value']
                        if country not in countries_counts:
                            countries_counts[country] = number_of_events
                        else:
                            countries_counts[country] += number_of_events
        return sorted(countries_counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_countries]

tester = GlobalStatisticsTester()
tester.test_collector()
