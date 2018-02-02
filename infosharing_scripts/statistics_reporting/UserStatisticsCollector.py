from StatisticsCollector import StatisticsCollector


class UserStatisticsCollector(StatisticsCollector):

    def count_submissions_from_user_within_duration(self, username, duration_start, duration_end):
        """
        Count the number of submissions from the given user within the duration start and end period, both inclusive.
        :param username: The name of the user whose submissions we are counting.
        :type username: string
        :param duration_start: The date such that all submissions considered were submitted no earlier than this date.
        :type duration_start: a Pendulum object
        :param duration_end: The date such that all submissions considered were submitted no later than this date.
        :type duration_end: a Pendulum object
        :return: dict, with keys 'ips' and 'events' whose values are ints, and key 'time_collected' whose value is a datetime
        """
        pipeline = [
            {
                '$match': {
                    'created': {
                        '$gte': duration_start,
                        '$lte': duration_end
                    }
                }
            },
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
        output_counts = {
            'ips': 0,
            'events': 0
        }
        # Note: There should be at most one result, because a $group operation on a null ID aggregates all documents.
        for aggregate_count in aggregate_counts:
            output_counts['ips'] = aggregate_count['numberOfIPs']
            output_counts['events'] = aggregate_count['numberOfEvents']
        return output_counts

    def count_excluded_events(self, username, duration_start, duration_end):
        """
        Count the number of Events that were submitted within the timeframe of the input duration, but were not saved to
        the database for one reason or another.
        :param username: The name of the user whose submissions we are counting.
        :type username: string
        :param duration_start: The date such that all submissions considered were submitted no earlier than this date.
        :type duration_start: a Pendulum object
        :param duration_end: The date such that all submissions considered were submitted no later than this date.
        :type duration_end: a Pendulum object
        :return: int
        """
        pipeline = [
            {
                '$match': {
                    'reporter': username,
                    'timeReceived': {
                        '$gte': duration_start,
                        '$lte': duration_end
                    }
                }
            },
            {'$count': "number_of_events"}
        ]
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        aggregate_count = self.staging_bad_events.aggregate(pipeline=pipeline, collation=collation, allowDiskUse=True)
        for count in aggregate_count:
            # Since final stage of aggregation was $count, there should only be one value to return.
            return count['number_of_events']
        return 0
