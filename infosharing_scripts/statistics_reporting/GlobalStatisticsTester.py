from datetime import datetime
import ipaddress
from GlobalStatisticsCollector import GlobalStatisticsCollector


class GlobalStatisticsTester:

    def __init__(self):
        self.collector = GlobalStatisticsCollector()
        self.invalid_ip_blocks = [
            ipaddress.ip_network(u'0.0.0.0/8'),  # IANA Local Identification Block
            ipaddress.ip_network(u'8.8.4.4/32'),  # Google Anycast DNS address
            ipaddress.ip_network(u'8.8.8.8/32'),  # Google Anycast DNS address
            ipaddress.ip_network(u'10.0.0.0/8'),  # Private address space
            ipaddress.ip_network(u'100.0.0.0/8'),  # Private address space
            ipaddress.ip_network(u'127.0.0.0/8'),  # Loopback block
            ipaddress.ip_network(u'169.254.0.0/16'),
            ipaddress.ip_network(u'172.16.0.0/12'),
            ipaddress.ip_network(u'192.0.0.0/24'),
            ipaddress.ip_network(u'192.0.2.0/24'),
            ipaddress.ip_network(u'192.168.0.0/16'),
            ipaddress.ip_network(u'198.18.0.0/15'),
            ipaddress.ip_network(u'198.51.100.0/24'),
            ipaddress.ip_network(u'203.0.113.0/24'),
            ipaddress.ip_network(u'208.67.222.222/32'),  # OpenDNS
            ipaddress.ip_network(u'224.0.0.0/4'),  # Multicast block (and more suggested by Rich)
            ipaddress.ip_network(u'225.0.0.0/8'),  # Multicast block
            ipaddress.ip_network(u'240.0.0.0/4')
        ]

    def is_valid_ip(self, ip_address):
        ip_address_object = ipaddress.ip_address(ip_address)
        for block in self.invalid_ip_blocks:
            if ip_address_object in block:
                return False
        return True

    def test_collector(self):
        # Note to self: Confirm total number of IPs and Events by simply running count queries in MongoDB shell.

        number_ips_multiple_reporters_collector = self.collector.count_ips_multiple_reporters()
        start_time = datetime.now()
        number_ips_multiple_reporters_manual = self.count_ips_multiple_reporters()
        duration = datetime.now() - start_time
        print "Duration to count IPs, multiple reporters, manual:", duration
        if number_ips_multiple_reporters_collector != number_ips_multiple_reporters_manual:
            print "Different count for number of IPs with multiple reporters."
            print "Collector:", number_ips_multiple_reporters_collector
            print "Manual:", number_ips_multiple_reporters_manual

        number_events_multiple_reporters_collector = self.collector.count_events_multiple_reporters()
        start_time = datetime.now()
        number_events_multiple_reporters_manual = self.count_events_multiple_reporters()
        duration = datetime.now() - start_time
        print "Duration to count Events, multiple reporters, manual:", duration
        if number_events_multiple_reporters_collector != number_events_multiple_reporters_manual:
            print "Different count for number of Events for IPs with multiple reporters."
            print "Collector:", number_events_multiple_reporters_collector
            print "Manual:", number_events_multiple_reporters_manual

        number_events_top_attack_types_collector = self.collector.count_events_top_attack_types_multiple_reporters()
        print number_events_top_attack_types_collector
        number_events_top_attack_types_manual = self.count_events_top_attack_types_multiple_reporters()
        print number_events_top_attack_types_manual

        number_events_top_attacking_countries_collector = self.collector.count_events_top_attacking_countries_multiple_reporters()
        print number_events_top_attacking_countries_collector
        number_events_top_attacking_countries_manual = self.count_events_top_attacking_countries_multiple_reporters()
        print number_events_top_attacking_countries_manual
        return

    def count_ips_multiple_reporters(self):
        ip_objects = self.collector.find_ips()
        count = 0
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if self.is_valid_ip(ip_address):
                for obj in ip_object['objects']:
                    if obj['type'] == 'Number of Reporters':
                        if int(obj['value']) > 1:
                            count += 1
                        break
        return count

    def count_events_multiple_reporters(self):
        """
        Count the number of Events corresponding to IP addresses that have been reported by multiple sources.
        :return: int
        """
        ip_objects = self.collector.find_ips()
        count = 0
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if self.is_valid_ip(ip_address):
                for obj in ip_object['objects']:
                    if obj['type'] == 'Number of Reporters':
                        if int(obj['value']) > 1:
                            count += len(ip_object['relationships'])
                        break
        return count

    def count_events_top_attack_types_multiple_reporters(self, number_of_attack_types=10):
        """
        Find the top attack types based on number of events with a given attack type and are for IPs with multiple
        reporters. Return the number of events for the top attack types.
        :param number_of_attack_types: The maximum number of attack types to return.
        :type number_of_attack_types: int
        :return: array of 2-tuples whose type is (string, int)
        """
        ip_objects = self.collector.find_ips()
        attack_type_counts = {}
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if self.is_valid_ip(ip_address):
                for obj in ip_object['objects']:
                    if obj['type'] == 'Number of Reporters':
                        if int(obj['value']) > 1:
                            relationships = ip_object['relationships']
                            for relationship in relationships:
                                event_id = relationship['value']
                                event_object = self.collector.events.find_one({'_id': event_id})
                                if event_object:
                                    for obj in event_object['objects']:
                                        if obj['type'] == 'Attack Type':
                                            attack_type = obj['value']
                                            if attack_type not in attack_type_counts:
                                                attack_type_counts[attack_type] = 1
                                            else:
                                                attack_type_counts[attack_type] += 1
                        break
        return sorted(attack_type_counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_attack_types]

    def count_events_top_attacking_countries_multiple_reporters(self, number_of_countries=10):
        """
        For each country, count the number of events corresponding to IP addresses whose geoIP information maps to that
        country and has been reported by multiple sources. Then, return only the countries with the highest counts
        (along with their counts).
        :param number_of_countries: The maximum number of countries to return.
        :type number_of_countries: int
        :return: array of 2-tuples whose type is (string, int)
        """
        pipeline = [
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
            if self.is_valid_ip(ip_address):
                number_of_events = len(ip_object['relationships'])
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
