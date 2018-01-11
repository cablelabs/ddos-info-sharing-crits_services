from StatisticsCollector import StatisticsCollector
from IPAddressChecker import IPAddressChecker


class GlobalStatisticsCollector(StatisticsCollector):

    def __init__(self):
        StatisticsCollector.__init__(self)
        self.ip_address_checker = IPAddressChecker()

    def count_ips_up_to_time(self, end_time):
        """
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :return: int
        """
        return self.ips.count(filter={'created': {'$lte': end_time}})

    def count_events_up_to_time(self, end_time):
        """
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :return: int
        """
        return self.events.count(filter={'created': {'$lte': end_time}})

    def count_submissions_multiple_reporters(self, end_time):
        """
        Count the number of Events corresponding to IP addresses where:
        1) The IP address has been reported by multiple sources.
        2) The IP address is not a bogon address (ex. 0.0.0.0).
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :return: dict with keys 'ips' and 'events', whose values are both of type int
        """
        pipeline = [
            {'$match': {'created': {'$lte': end_time}}},
            {
                '$project': {
                    '_id': 0,
                    'ip': 1,
                    'objects': 1,
                    'numberOfEvents': {'$size': '$relationships'}
                }
            },
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
        ip_objects = self.ips.aggregate(pipeline, collation=collation, allowDiskUse=True)
        counts = {
            'ips': 0,
            'events': 0
        }
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if self.ip_address_checker.is_valid_ip(ip_address):
                counts['ips'] += 1
                counts['events'] += ip_object['numberOfEvents']
        return counts

    def count_events_top_attack_types_multiple_reporters(self, end_time, number_of_attack_types=10):
        """
        Find the top attack types based on number of Events for each attack type, and return the number of Events for
        these top attack types. Only counts Events for IPs where:
        1) The IP address has been reported by multiple sources.
        2) The IP address is not a bogon address (ex. 0.0.0.0).
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :param number_of_attack_types: The maximum number of attack types to return.
        :type number_of_attack_types: int
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
        ip_objects = self.ips.aggregate(pipeline, collation=collation, allowDiskUse=True)
        ids_of_events_to_find = []
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if self.ip_address_checker.is_valid_ip(ip_address):
                relationships = ip_object['relationships']
                for relationship in relationships:
                    event_id = relationship['value']
                    ids_of_events_to_find.append(event_id)
        i = 0
        number_of_ids = 100
        attack_type_counts = {}
        while i < len(ids_of_events_to_find):
            ids_subset = ids_of_events_to_find[i:i+number_of_ids]
            query = {'_id': {'$in': ids_subset}}
            event_objects = self.events.find(filter=query)
            for event_object in event_objects:
                for obj in event_object['objects']:
                    if obj['type'] == 'Attack Type':
                        attack_type = obj['value']
                        if attack_type not in attack_type_counts:
                            attack_type_counts[attack_type] = 1
                        else:
                            attack_type_counts[attack_type] += 1
            i += number_of_ids
        return sorted(attack_type_counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_attack_types]

    def count_events_top_attacking_countries_multiple_reporters(self, end_time, number_of_countries=10):
        """
        Find the top attacking countries, and return the number of Events for these top attacking countries. This is
        done by taking each country and counting the number of Events corresponding to IP addresses whose geoIP
        information maps to that country. Only counts Events for IPs that have been reported by multiple sources.
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :param number_of_countries: The maximum number of countries to return.
        :type number_of_countries: int
        :return: array of 2-tuples whose type is (string, int), sorted on 2nd value in descending order
        """
        ip_objects = self.ips.find(filter={'created': {'$lte': end_time}})
        countries_counts = {}
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if self.ip_address_checker.is_valid_ip(ip_address):
                country = ''
                number_of_reporters = 0
                for obj in ip_object['objects']:
                    if obj['type'] == 'Country':
                        country = obj['value']
                    elif obj['type'] == 'Number of Reporters':
                        number_of_reporters = int(obj['value'])
                if number_of_reporters > 1:
                    number_of_events = len(ip_object['relationships'])
                    if country not in countries_counts:
                        countries_counts[country] = number_of_events
                    else:
                        countries_counts[country] += number_of_events
        return sorted(countries_counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_countries]
