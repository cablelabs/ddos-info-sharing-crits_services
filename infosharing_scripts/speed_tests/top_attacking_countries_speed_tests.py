from datetime import datetime
from dateutil.relativedelta import relativedelta
import pandas
from pymongo import MongoClient


class TopCountriesTest:
    """
    This class tests multiple functions that count the top attacking countries, for events regarding IP addresses that
    were reported by more than one user.
    """

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users

    def version_1(self, number_of_countries=10):
        """
        For each country, count the number of events corresponding to IP addresses whose geoIP information maps to that
        country and has been reported by multiple sources. Then, return only the countries with the highest counts
        (along with their counts).

        This version iterates over all IPs and counts the number of Events corresponding to them.
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

    # TODO: Maybe finish this version someday
    def top_attacking_country_multiple_reporters_counts_v1(self, number_of_countries=10):
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
                    '$or': [
                        {'objects.type': 'Country'},
                        {'objects.type': 'Number of Reporters'}
                    ]
                }
            },
            {
                '$project': {
                    'country': {
                        '$cond': [
                            {'$eq': ['$objects.type', 'Country']},
                            '$objects.value',
                            ''
                        ]
                    },
                    'numberOfReporters': {
                        '$cond': [
                            {'$eq': ['$objects.type', 'Number of Reporters']},
                            '$objects.value',
                            ''
                        ]
                    },
                    'numberOfEvents': 1
                }
            },
            {
                '$group': {
                    '_id': '$id',
                    'country': 0
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

    # Another Idea: a version where, in the aggregation query,