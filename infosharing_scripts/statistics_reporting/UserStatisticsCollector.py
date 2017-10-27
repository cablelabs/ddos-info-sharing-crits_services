from datetime import datetime, timedelta
from StatisticsCollector import StatisticsCollector


class UserStatisticsCollector(StatisticsCollector):

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
