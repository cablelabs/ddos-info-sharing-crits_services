from datetime import datetime, timedelta
from dateutils import relativedelta
from pymongo import MongoClient


class MongoDBFunctionsWrapper:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users

    ### Find Functions ###

    def find_users(self):
        return self.users.find()

    ### Count Functions for Global Statistics ###

    def count_ips(self):
        return self.ips.count()

    def count_events(self):
        return self.events.count()

    def count_ips_multiple_reporters(self):
        """
        Count the number of IP addresses that have been reported by multiple sources.
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

    ### Count Function for User Statistics ###

    def count_submissions_from_user_within_day(self, username):
        """
        Count the number of submissions from the given user within the last day (24 hrs).
        :param username: The name of the user whose submissions we are counting.
        :type username: string
        :return: dict, with keys 'ips' and 'events' whose values are ints
        """
        end_period = datetime.now()
        # TODO: Should I round up or down for the datetime I use to filter? Should I round at all?
        start_period = end_period - timedelta(days=120)
        pipeline = [
            {'$match': {'created': {'$gte': start_period}}},
            {'$unwind': '$source'},
            {'$unwind': '$source.instances'},
            {'$match': {'source.instances.analyst': username}},
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
            {
                '$group': {
                    '_id': '$ip.ip',
                    'numberOfEvents': {'$sum': 1}
                }
            },
            {
                '$group': {
                    '_id': None,
                    'numberOfIPs': {'$sum': 1},
                    'numberOfEvents': {'$sum': '$numberOfEvents'}
                }
            }
        ]
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        aggregate_counts = self.events.aggregate(pipeline=pipeline, collation=collation, allowDiskUse=True)
        for count in aggregate_counts:
            # Return values from first result, because there should only be one result.
            counts = {
                'ips': count['numberOfIPs'],
                'events': count['numberOfEvents']
            }
            return counts
        counts = {
            'ips': 0,
            'events': 0
        }
        return counts

    ### Functions for Private Statistics ###

    def top_attacking_asn_counts(self, number_of_attack_types=10):
        pipeline = [
            {
                '$project': {
                    '_id': 0,
                    'objects': 1,
                    'numberOfEvents': {'$size': '$relationships'}
                }
            },
            {'$unwind': '$objects'},
            {'$match': {'objects.type': 'AS Number'}},
            {
                '$project': {
                    'asn': '$objects.value',
                    'numberOfEvents': 1
                }
            },
            {
                '$group': {
                    '_id': '$asn',
                    'count': {'$sum': '$numberOfEvents'}
                }
            },
            {'$sort': {'count': -1}},
            {'$limit': number_of_attack_types}
        ]
        results = self.ips.aggregate(pipeline, allowDiskUse=True)
        counts = {}
        for result in results:
            as_number = result['_id']
            count = result['count']
            counts[as_number] = count
        return counts

    def count_events_top_attacking_asns_multiple_reporters(self, number_of_asns=10):
        raise NotImplementedError

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

    def count_submissions_per_owning_source(self):
        counts = {}
        source_names = self.source_access.find(projection={'name': 1})
        for entry in source_names:
            source_name = entry['name']
            pipeline = [
                {'$match': {'releasability.name': source_name}},
                {'$project': {'numberOfEvents': {'$size': '$relationships'}}},
                {
                    '$group': {
                        '_id': None,
                        'count': {'$sum': '$numberOfEvents'}
                    }
                },
            ]
            aggregation_counts = self.ips.aggregate(pipeline, allowDiskUse=True)
            number_of_events = 0
            # Note: There should only be one result, but still need for-loop to get value of result.
            for count in aggregation_counts:
                number_of_events = count['count']
            counts_per_source = {
                'ips': self.ips.count({'releasability.name': source_name}),
                'events': number_of_events
            }
            counts[source_name] = counts_per_source
        return counts
