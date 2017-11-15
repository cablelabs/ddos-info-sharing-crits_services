from StatisticsCollector import StatisticsCollector


class GlobalStatisticsCollector(StatisticsCollector):

    def count_ips(self):
        return self.ips.count()

    def count_events(self):
        return self.events.count()

    def count_ips_multiple_reporters(self):
        """
        Count the number of IP addresses that ...validated. There are two criteria:
        1) The IP address has been reported by multiple sources.
        2) The IP address is not a bogon address.
        :return:
        """
        pipeline = [
            {'$unwind': '$objects'},
            {
                '$match': {
                    'objects.type': 'Number of Reporters',
                    'objects.value': {'$gt': "1"}
                }
            },
            {
                '$group': {
                    '_id': None,
                    'count': {'$sum': 1}
                }
            }
        ]
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        counts = self.ips.aggregate(pipeline, collation=collation, allowDiskUse=True)
        for count in counts:
            # Return first result, because there should only be one result.
            return count['count']

    def count_events_multiple_reporters(self):
        """
        Count the number of Events corresponding to IP addresses that have been reported by multiple sources.
        :return: int
        """
        pipeline = [
            {
                '$project': {
                    '_id': 0,
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
            },
            {
                '$group': {
                    '_id': None,
                    'count': {'$sum': '$numberOfEvents'}
                }
            },
        ]
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        counts = self.ips.aggregate(pipeline, collation=collation, allowDiskUse=True)
        for count in counts:
            # Return first result, because there should only be one result.
            return count['count']

    def count_events_top_attack_types(self, number_of_attack_types=10):
        pipeline = [
            {'$unwind': '$objects'},
            {'$match': {'objects.type': 'Attack Type'}},
            {
                '$group': {
                    '_id': '$objects.value',
                    'count': {'$sum': 1}
                }
            },
            {'$sort': {'count': -1}},
            {'$limit': number_of_attack_types}
        ]
        results = self.events.aggregate(pipeline, allowDiskUse=True)
        counts = {}
        for result in results:
            attack_type = result['_id']
            count = result['count']
            counts[attack_type] = count
        return counts

    def count_events_top_attack_types_multiple_reporters(self, number_of_attack_types=10):
        """
        Find the top attack types based on number of events with a given attack type and are for IPs with multiple
        reporters. Return the number of events for the top attack types.
        :param number_of_attack_types: The maximum number of attack types to return.
        :type number_of_attack_types: int
        :return: array of 2-tuples whose type is (string, int)
        """
        pipeline = [
            {'$unwind': '$relationships'},
            {
                '$lookup': {
                    'from': 'ips',
                    'localField': 'relationships.value',
                    'foreignField': '_id',
                    'as': 'ip'
                }
            },
            {'$unwind': '$ip'},
            {'$unwind': '$ip.objects'},
            {
                '$match': {
                    'ip.objects.type': 'Number of Reporters',
                    'ip.objects.value': {'$gt': '1'}
                }
            },
            {'$unwind': '$objects'},
            {'$match': {'objects.type': 'Attack Type'}},
            {'$project': {'attackType': '$objects.value'}},
            {
                '$group': {
                    '_id': 'attackType',
                    'count': {'$sum': 1}
                }
            },
            {'$sort': {'count': -1}},
            {'$limit': number_of_attack_types}
        ]
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        attack_type_counts = self.events.aggregate(pipeline=pipeline, collation=collation, allowDiskUse=True)
        counts = {}
        for result in attack_type_counts:
            attack_type = result['_id']
            count = result['count']
            counts[attack_type] = count
        return sorted(counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_attack_types]

    def count_events_top_attacking_countries(self, number_of_countries=10):
        pipeline = [
            {
                '$project': {
                    '_id': 0,
                    'objects': 1,
                    'numberOfEvents': {'$size': '$relationships'}
                }
            },
            {'$unwind': '$objects'},
            {'$match': {'objects.type': 'Country'}},
            {
                '$project': {
                    'country': '$objects.value',
                    'numberOfEvents': 1
                }
            },
            {
                '$group': {
                    '_id': '$country',
                    'count': {'$sum': '$numberOfEvents'}
                }
            },
            {'$sort': {'count': -1}},
            {'$limit': number_of_countries}
        ]
        results = self.ips.aggregate(pipeline, allowDiskUse=True)
        counts = {}
        for result in results:
            country = result['_id']
            count = result['count']
            counts[country] = count
        return counts

    def count_events_top_attacking_countries_multiple_reporters(self, number_of_countries=10):
        """
        For each country, count the number of events corresponding to IP addresses whose geoIP information maps to that
        country and has been reported by multiple sources. Then, return only the countries with the highest counts
        (along with their counts).
        :param number_of_countries: The maximum number of countries to return.
        :type number_of_countries: int
        :return: array of 2-tuples whose type is (string, int)
        """
        ip_objects = self.ips.find()
        counts = {}
        for ip_object in ip_objects:
            country = ''
            number_of_reporters = 0
            for obj in ip_object['objects']:
                if obj['type'] == 'Country':
                    country = obj['value']
                elif obj['type'] == 'Number of Reporters':
                    number_of_reporters = int(obj['value'])
            if number_of_reporters > 1:
                number_of_events = len(ip_object['relationships'])
                if country in counts:
                    counts[country] += number_of_events
                else:
                    counts[country] = number_of_events
        return sorted(counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_countries]
