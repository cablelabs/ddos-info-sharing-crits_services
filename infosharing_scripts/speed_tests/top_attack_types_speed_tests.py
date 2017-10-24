from datetime import datetime
from dateutil.relativedelta import relativedelta
import pandas
from pymongo import MongoClient


class AttackTypeTests:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users

    def run(self):
        try:
            #self.count_events_top_attack_types_multiple_reporters_v1()
            #self.count_events_top_attack_types_multiple_reporters_v2()
            #self.top_attack_type_counts()
            #self.count_events_top_attack_types_multiple_reporters_v3()
            #self.count_events_top_attack_types_multiple_reporters_v4()
            #self.count_events_top_attack_types_multiple_reporters_v5()
            self.version_6()
        except Exception as e:
            print e.message

    def count_events_top_attack_types_multiple_reporters_v1(self, number_of_attack_types=10):
        """
        For each attack type, count the number of events that have that attack type and correspond to IP addresses that
        have been reported by multiple sources. Then, return only the attack types with the highest counts (along with
        their counts).

        This version just iterates through each IP object and each Event within IP objects that have multiple reporters.
        In testing, I found this version was way too slow. It never finished after an hour or more.
        :param number_of_attack_types: The maximum number of countries to return.
        :type number_of_attack_types: int
        :return: array of 2-tuples whose type is (string, int)
        """
        print "Version 1:"
        ip_objects = self.ips.find()
        counts = {}
        start_time = datetime.now()
        for ip_object in ip_objects:
            number_of_reporters = 0
            for obj in ip_object['objects']:
                if obj['type'] == 'Number of Reporters':
                    number_of_reporters = int(obj['value'])
                    break
            if number_of_reporters > 1:
                for relationship in ip_object['relationships']:
                    if relationship['type'] == 'Event':
                        event_id = relationship['value']
                        event_object = self.events.find_one({'_id': event_id})
                        for obj in event_object['objects']:
                            if obj['type'] == 'Attack Type':
                                attack_type = obj['value']
                                if attack_type in counts:
                                    counts[attack_type] += 1
                                else:
                                    counts[attack_type] = 1
        duration = datetime.now() - start_time
        print "Time to iterate over IPs:", duration
        start_time = datetime.now()
        result = sorted(counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_attack_types]
        duration = datetime.now() - start_time
        print "Time to sort:", duration
        return result

    def count_events_top_attack_types_multiple_reporters_v2(self, number_of_attack_types=10):
        """
        This version does an aggregation query on the IPs collection.
        Initial testing showed this version was also too slow when it got to the group stage.
        :param number_of_attack_types:
        :return: dict, where keys are strings and values are ints
        """
        print "Version 2:"
        pipeline = [
            {'$unwind': '$objects'},
            {
                '$match': {
                    'objects.type': 'Number of Reporters',
                    'objects.value': {'$gt': "1"}
                }
            },
            {'$unwind': '$relationships'},
            {'$match': {'relationships.type': 'Event'}},
            {
                '$lookup': {
                    'from': 'events',
                    'localField': 'relationships.value',
                    'foreignField': '_id',
                    'as': 'event'
                }
            },
            {'$unwind': '$event'},
            {'$unwind': '$event.objects'},
            {'$match': {'event.objects.type': 'Attack Type'}},
            {
                '$group': {
                    '_id': '$event.objects.value',
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
        # for i in range(0, len(pipeline)):
        #     stage_number = i+1
        #     start_time = datetime.now()
        attack_type_counts = self.ips.aggregate(pipeline=pipeline, collation=collation, allowDiskUse=True)
        #     duration = datetime.now() - start_time
        #     print "Time for stages up to stage", stage_number, ":", duration
        counts = {}
        for result in attack_type_counts:
            attack_type = result['_id']
            count = result['count']
            counts[attack_type] = count
        return counts

    def top_attack_type_counts(self, number_of_attack_types=10):
        """
        Initial testing showed that this takes around 4 min, 30 sec to run.
        :param number_of_attack_types:
        :return:
        """
        print "Version without filter on 'Number of Reporters':"
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
        start_time = datetime.now()
        results = self.events.aggregate(pipeline, allowDiskUse=True)
        duration = datetime.now() - start_time
        print "Aggregation time:", duration
        counts = {}
        for result in results:
            attack_type = result['_id']
            count = result['count']
            counts[attack_type] = count
        return counts

    def count_events_top_attack_types_multiple_reporters_v3(self, number_of_attack_types=10):
        """
        This version does an aggregation query on the Events collection.
        :param number_of_attack_types:
        :return: dict, where keys are strings and values are ints
        """
        print "Version 3:"
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
            {
                '$project': {
                    'attackType': '$objects.value'
                }
            },
            #{'$count': "count"}
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
        for i in range(0, len(pipeline)):
            stage_number = i+1
            start_time = datetime.now()
            attack_type_counts = self.events.aggregate(pipeline=pipeline[:stage_number], collation=collation, allowDiskUse=True)
            duration = datetime.now() - start_time
            print "Time for stages up to stage", stage_number, ":", duration
        counts = {}
        for result in attack_type_counts:
            attack_type = result['_id']
            count = result['count']
            counts[attack_type] = count
        return counts

    def count_events_top_attack_types_multiple_reporters_v4(self, number_of_attack_types=10):
        """
        This version just iterates across each Event, and looks for IPs that have been reported by multiple users.
        :param number_of_attack_types:
        :return: array of 2-tuples whose type is (string, int)
        """
        print "Version 4:"
        event_objects = self.events.find()
        counts = {}
        start_time = datetime.now()
        for event_object in event_objects:
            # Note: There should only be one relationship for any single event.
            for relationship in event_object['relationships']:
                ip_id = relationship['value']
                ip_object = self.ips.find_one({'_id': ip_id})
                for obj in ip_object['objects']:
                    if obj['type'] == 'Number of Reporters':
                        if int(obj['value']) > 1:
                            for event_obj in event_object['objects']:
                                if event_obj['type'] == 'Attack Type':
                                    attack_type = event_obj['value']
                                    if attack_type in counts:
                                        counts[attack_type] += 1
                                    else:
                                        counts[attack_type] = 1
                        break
        duration = datetime.now() - start_time
        print "Time to iterate over Events:", duration
        start_time = datetime.now()
        result = sorted(counts.iteritems(), key=lambda (k, v): v, reverse=True)[:number_of_attack_types]
        duration = datetime.now() - start_time
        print "Time to sort:", duration
        return result

    # TODO: work from here, as this is best version
    def count_events_top_attack_types_multiple_reporters_v5(self, number_of_attack_types=10):
        print "Version 5:"
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
            {
                '$project': {
                    'attackType': '$objects.value'
                }
            },
            # {'$count': "count"}
            # {
            #     '$group': {
            #         '_id': 'attackType',
            #         'count': {'$sum': 1}
            #     }
            # },
            # {'$sort': {'count': -1}},
            # {'$limit': number_of_attack_types}
        ]
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        for i in range(0, len(pipeline)):
            stage_number = i + 1
            start_time = datetime.now()
            attack_type_counts = self.events.aggregate(pipeline=pipeline[:stage_number], collation=collation,
                                                       allowDiskUse=True)
            duration = datetime.now() - start_time
            print "Time for stages up to stage", stage_number, ":", duration
        start_time = datetime.now()
        attack_types = list(attack_type_counts)
        duration = datetime.now() - start_time
        print "Time to convert to list:", duration
        attack_types_dataframe = pandas.DataFrame.from_records(attack_types)
        results = attack_types_dataframe.groupby(columns=['attackType']).size()
        # TODO: Use 'results' variable somehow.
        counts = {}
        for result in attack_type_counts:
            attack_type = result['_id']
            count = result['count']
            counts[attack_type] = count
        return counts
        # attack_types_dataframe = attack_types_dataframe.assign(attack_type=attack_types_dataframe.attackType)

    def version_6(self, number_of_attack_types=10):
        """
        This version does an aggregation query on the Events collection, but does so in a way where it grabs
        non-overlapping date ranges, 30 days at a time.
        :param number_of_attack_types:
        :return: dict, where keys are strings and values are ints
        """
        print "Version 6:"
        counts = {}
        start_period = datetime(year=2017, month=6, day=1)
        current_period = start_period
        today = datetime.today()
        # For each time period, count number of events for each attack type within that period
        days_analyzed = 0
        complete_results = None
        while current_period < today:
            next_period = current_period + relativedelta(days=1)
            pipeline = [
                {
                    '$match': {
                        'created': {
                            '$gte': current_period,
                            '$lt': next_period
                        }
                    }
                },
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
                {
                    '$project': {
                        'attackType': '$objects.value'
                    }
                },
                # {
                #     '$group': {
                #         '_id': 'attackType',
                #         'count': {'$sum': 1}
                #     }
                # },
                # {'$sort': {'count': -1}},
                # {'$limit': number_of_attack_types}
            ]
            collation = {
                'locale': 'en_US_POSIX',
                'numericOrdering': True
            }
            start_time = datetime.now()
            attack_type_counts = self.events.aggregate(pipeline=pipeline, collation=collation, allowDiskUse=True)
            duration = datetime.now() - start_time
            print "Aggregation Time:", duration

            start_time = datetime.now()
            attack_types = list(attack_type_counts)
            duration = datetime.now() - start_time
            print "Time to convert to list:", duration
            attack_types_dataframe = pandas.DataFrame.from_records(attack_types)
            # dataframe.shape[0] says how many rows are in the dataframe.
            if attack_types_dataframe.shape[0] > 0:
                if not complete_results:
                    complete_results = attack_types_dataframe.groupby('attackType').size()
                    print complete_results
                else:
                    results = attack_types_dataframe.groupby('attackType').size()
                    print results
                    complete_results.append(results)
                    print complete_results
                    complete_results = complete_results.groupby('attackType').sum()
                    print complete_results
                # TODO: Use 'results' variable somehow.
            days_analyzed += 1
            print "Days Analyzed:", days_analyzed
            current_period = next_period
        return counts


test = AttackTypeTests()
test.run()
