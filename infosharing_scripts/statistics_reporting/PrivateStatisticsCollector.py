from datetime import datetime, timedelta
from dateutils import relativedelta
from StatisticsCollector import StatisticsCollector


class PrivateStatisticsCollector(StatisticsCollector):

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
