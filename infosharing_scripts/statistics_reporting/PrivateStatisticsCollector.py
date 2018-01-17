from datetime import datetime
from dateutils import relativedelta
from StatisticsCollector import StatisticsCollector
from IPAddressChecker import IPAddressChecker


class PrivateStatisticsCollector(StatisticsCollector):

    def __init__(self):
        StatisticsCollector.__init__(self)
        self.ip_address_checker = IPAddressChecker()

    def top_attacking_asn_counts(self, number_of_asns=10):
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
            {'$limit': number_of_asns}
        ]
        results = self.ips.aggregate(pipeline, allowDiskUse=True)
        counts = {}
        for result in results:
            as_number = result['_id']
            count = result['count']
            counts[as_number] = count
        return counts

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
        ip_objects = self.ips.find(filter={'created': {'$lte': end_time}})
        asns_counts = {}
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            if self.ip_address_checker.is_valid_ip(ip_address):
                asn = ''
                number_of_reporters = 0
                for obj in ip_object['objects']:
                    if obj['type'] == 'AS Number':
                        asn = obj['value']
                    elif obj['type'] == 'Number of Reporters':
                        number_of_reporters = int(obj['value'])
                if number_of_reporters > 1:
                    number_of_events = len(ip_object['relationships'])
                    if asn not in asns_counts:
                        asns_counts[asn] = number_of_events
                    else:
                        asns_counts[asn] += number_of_events
        return sorted(asns_counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_asns]

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
