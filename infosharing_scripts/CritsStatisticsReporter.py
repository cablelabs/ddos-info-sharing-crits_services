import csv
from datetime import datetime
from pymongo import MongoClient


class CritsStatisticsReporter:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users

    def run(self):
        full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        time_now = datetime.now()
        time_now_str = time_now.strftime(full_time_format)
        csv_file = open('global_statistics_'+time_now_str+'.csv', 'wb')
        stats_writer = csv.writer(csv_file)
        stats_writer.writerow(['Statistic', 'Value'])

        total_ips = self.ips.count()
        stats_writer.writerow(['Total # of IPs', total_ips])
        print "Wrote total number of IPs."

        total_events = self.events.count()
        stats_writer.writerow(['Total # of Events', total_events])
        print "Wrote total number of Events."

        number_ips_reported_by_many_sources = self.count_ips_reported_by_multiple_sources()
        stats_writer.writerow(['Number of IPs reported by more than one data provider', number_ips_reported_by_many_sources])
        print "Wrote number of IPs reported by more than one data provider."

        stats_writer.writerow([])
        stats_writer.writerow(['Top Attack Types'])
        stats_writer.writerow(['Attack Type', 'Number of Events'])
        top_attack_type_counts = self.top_attack_type_counts(10)
        rank = 1
        for attack_type, count in sorted(top_attack_type_counts.iteritems(), key=lambda (k,v): v, reverse=True):
            stats_writer.writerow([attack_type, count])
            rank += 1
        print "Wrote top 10 attack types."

        stats_writer.writerow([])
        stats_writer.writerow(['Top Attacking Countries'])
        stats_writer.writerow(['Country', 'Number of Events'])
        top_attacking_country_counts = self.top_attacking_country_counts(10)
        rank = 1
        for country, count in sorted(top_attacking_country_counts.iteritems(), key=lambda (k,v): v, reverse=True):
            stats_writer.writerow([country, count])
            rank += 1
        print "Wrote top 10 attacking countries."

        # NOTE: DO NOT email this to ISPs.
        stats_writer.writerow([])
        stats_writer.writerow(['Top Attacking ASNs'])
        stats_writer.writerow(['ASN', 'Number of Events'])
        top_attacking_asn_counts = self.top_attacking_asn_counts(10)
        rank = 1
        for as_number, count in sorted(top_attacking_asn_counts.iteritems(), key=lambda (k,v): v, reverse=True):
            stats_writer.writerow([as_number, count])
            rank += 1
        print "Wrote top 10 attacking ASNs."

        csv_file.close()

    def count_ips_reported_by_multiple_sources(self):
        unwind_objects_stage = {'$unwind': '$objects'}
        match_multiple_reporters_stage = {
            '$match': {
                'objects.type': 'Number of Reporters',
                'objects.value': {'$gt': "1"}
            }
        }
        group_count_stage = {
            '$group': {
                '_id': None,
                'count': {'$sum': 1}
            }
        }
        pipeline = [
            unwind_objects_stage,
            match_multiple_reporters_stage,
            group_count_stage
        ]
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        counts = self.ips.aggregate(pipeline, collation=collation, allowDiskUse=True)
        for count in counts:
            # Return first result, because there should only be one result.
            return count['count']

    def top_attack_type_counts(self, number_of_attack_types=10):
        unwind_objects_stage = {'$unwind': '$objects'}
        match_attack_type_object_stage = {
            '$match': {
                'objects.type': 'Attack Type'
            }
        }
        group_attack_type_value_stage = {
            '$group': {
                '_id': '$objects.value',
                'count': {'$sum': 1}
            }
        }
        sort_by_count_stage = {
            '$sort': {
                'count': -1
            }
        }
        limit_stage = {'$limit': number_of_attack_types}
        pipeline = [
            unwind_objects_stage,
            match_attack_type_object_stage,
            group_attack_type_value_stage,
            sort_by_count_stage,
            limit_stage
        ]
        results = self.events.aggregate(pipeline, allowDiskUse=True)
        counts = {}
        for result in results:
            attack_type = result['_id']
            count = result['count']
            counts[attack_type] = count
        return counts

    def top_attacking_country_counts(self, number_of_attack_types=10):
        project_important_fields_stage = {
            '$project': {
                '_id': 0,
                'objects': 1,
                'numberOfEvents': {
                    '$size': '$relationships'
                }
            }
        }
        unwind_objects_stage = {'$unwind': '$objects'}
        match_country_stage = {
            '$match': {
                'objects.type': 'Country'
            }
        }
        project_country_stage = {
            '$project': {
                'country': '$objects.value',
                'numberOfEvents': 1
            }
        }
        group_by_country_stage = {
            '$group': {
                '_id': '$country',
                'count': {
                    '$sum': '$numberOfEvents'
                }
            }
        }
        sort_by_count_stage = {
            '$sort': {
                'count': -1
            }
        }
        limit_stage = {'$limit': number_of_attack_types}
        pipeline = [
            project_important_fields_stage,
            unwind_objects_stage,
            match_country_stage,
            project_country_stage,
            group_by_country_stage,
            sort_by_count_stage,
            limit_stage
        ]
        results = self.ips.aggregate(pipeline, allowDiskUse=True)
        counts = {}
        for result in results:
            country = result['_id']
            count = result['count']
            counts[country] = count
        return counts

    def top_attacking_asn_counts(self, number_of_attack_types=10):
        project_important_fields_stage = {
            '$project': {
                '_id': 0,
                'objects': 1,
                'numberOfEvents': {
                    '$size': '$relationships'
                }
            }
        }
        unwind_objects_stage = {'$unwind': '$objects'}
        match_asn_stage = {
            '$match': {
                'objects.type': 'AS Number'
            }
        }
        project_asn_stage = {
            '$project': {
                'asn': '$objects.value',
                'numberOfEvents': 1
            }
        }
        group_by_asn_stage = {
            '$group': {
                '_id': '$asn',
                'count': {
                    '$sum': '$numberOfEvents'
                }
            }
        }
        sort_by_count_stage = {
            '$sort': {
                'count': -1
            }
        }
        limit_stage = {'$limit': number_of_attack_types}
        pipeline = [
            project_important_fields_stage,
            unwind_objects_stage,
            match_asn_stage,
            project_asn_stage,
            group_by_asn_stage,
            sort_by_count_stage,
            limit_stage
        ]
        results = self.ips.aggregate(pipeline, allowDiskUse=True)
        counts = {}
        for result in results:
            as_number = result['_id']
            count = result['count']
            counts[as_number] = count
        return counts


# TODO: create text file for each user.
# TODO: email data to users
# Their files include: number of submissions from that user, ...


stats_reporter = CritsStatisticsReporter()
stats_reporter.run()
