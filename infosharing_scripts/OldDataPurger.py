import csv
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from pymongo import MongoClient
# TODO: why do I use relativedelta instead of timedelta?

class OldDataPurger:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users

    def run(self):
        full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        time_now = datetime.now() # could also be datetime.today()
        time_now_str = time_now.strftime(full_time_format)

        submission_counts_before = self.count_old_and_new_submissions(time_now)
        submission_counts_before_row = [
            'Before',
            submission_counts_before['old_ips'],
            submission_counts_before['new_ips'],
            submission_counts_before['old_events'],
            submission_counts_before['new_events']
        ]

        self.remove_old_events(time_now, time_now_str)
        #self.update_event_relationships_all_ips(time_now_str)
        # TODO: Redo analytics on IPs that had events removed. Would like to avoid unnecessary work if IP has no events
        # and we plan on removing it anyways.
        #self.remove_ips_with_no_events(time_now_str)

        submission_counts_after = self.count_old_and_new_submissions(time_now)
        submission_counts_after_row = [
            'After',
            submission_counts_after['old_ips'],
            submission_counts_after['new_ips'],
            submission_counts_after['old_events'],
            submission_counts_after['new_events']
        ]
        submission_counts_file = open('submission_counts_' + time_now_str + '.csv', 'wb')
        submission_counts_writer = csv.writer(submission_counts_file)
        submission_counts_writer.writerow(['Time', 'Old IPs', 'New IPs', 'Old Events', 'New Events'])
        submission_counts_writer.writerow(submission_counts_before_row)
        submission_counts_writer.writerow(submission_counts_after_row)
        submission_counts_file.close()
        # output_lines = ['{0}\n'.format(line) for line in output_lines]
        # cron_job_file = open('clear_data_stats_'+time_now_str+'.txt', 'w')
        # cron_job_file.writelines(output_lines)
        # cron_job_file.close()

    def count_old_and_new_submissions(self, time_now):
        """
        Return counts of the number of IPs and Events that are considered "old" or "new".
        "Old" Events are those that were created over 1 month ago from "time_now".
        :param time_now: The time such that all data older than 1 month from this time is considered "old".
        :type time_now: datetime
        :return: dict
        """
        counts = {}
        # TODO: how handle months with 31 days, and how handle February?
        one_month_ago = time_now - timedelta(days=30)
        # Filter IPs based on 'modified' date because the "old" IPs are those whose latest Event is still considered
        # "old", and IPs with new Events may have been created long before their latest Event was added.
        # TODO: 'modified' won't work, because IP is modified shortly after the latest event was submitted.
        # It gets modified by analytics service at a later time.
        old_ips_query = {
            'modified': {
                '$lt': one_month_ago
            }
        }
        counts['old_ips'] = self.ips.count(filter=old_ips_query)
        new_ips_query = {
            'modified': {
                '$gte': one_month_ago
            }
        }
        counts['new_ips'] = self.ips.count(filter=new_ips_query)
        old_events_query = {
            'created': {
                '$lt': one_month_ago
            }
        }
        counts['old_events'] = self.events.count(filter=old_events_query)
        new_events_query = {
            'created': {
                '$gte': one_month_ago
            }
        }
        counts['new_events'] = self.events.count(filter=new_events_query)
        return counts

    def remove_old_events(self, time_now, time_now_str):
        one_month_ago = time_now - timedelta(days=30)
        query = {
            'created': {
                '$lt': one_month_ago
            }
        }
        #result = self.events.delete_many(filter=query)
        events = self.events.find(filter=query)
        event_deletion_log = open('event_deletion_log_'+time_now_str+'.csv', 'wb')
        event_deletion_log_writer = csv.writer(event_deletion_log)
        event_deletion_log_writer.writerow(['_id', 'title', 'created'])
        for event in events:
            event_row = [event['_id'], event['title'], event['created']]
            event_deletion_log_writer.writerow(event_row)
            delete_query = {'_id': event['_id']}
            self.events.delete_one(filter=delete_query)
        event_deletion_log.close()

    # TODO: test methods of filtering relationships on events. One just iterates over relationships field.
    # Another method does aggregation. There might also be a Python function that could filter the relationships array.
    # Version 1 (below): just iterate, don't try anymore MongoDB tricks I don't know off-hand
    def update_event_relationships_all_ips(self, time_now_str):
        """
        For all IPs, remove relationships that reference Events which no longer exist.
        :return: (nothing)
        """
        ip_objects = self.ips.find()
        relationship_deletion_log = open('relationship_deletion_log_'+time_now_str+'.csv', 'wb')
        relationship_deletion_log_writer = csv.writer(relationship_deletion_log)
        relationship_deletion_log_writer.writerow(['ip', 'relationship_id', 'event_id'])
        for ip_object in ip_objects:
            # Dictionary of IDs of relationships to remove, each paired with ID of its associated Event.
            relationship_event_id_pairs_to_remove = {}
            for relationship in ip_object['relationships']:
                if relationship['type'] == 'Event':
                    event_id = relationship['value']
                    event = self.events.find_one({'_id': event_id})
                    if not event:
                        relationship_event_id_pairs_to_remove[relationship['_id']] = event_id
            for relationship_id, event_id in relationship_event_id_pairs_to_remove.iteritems():
                relationship_row = [ip_object['ip'], relationship_id, event_id]
                relationship_deletion_log_writer.writerow(relationship_row)
            query = {'_id': ip_object['_id']}
            update = {
                '$pull': {
                    'relationships.id': {
                        '$in': relationship_event_id_pairs_to_remove.keys()
                    }
                }
            }
            self.ips.update_one(filter=query, update=update)
        relationship_deletion_log.close()

    def remove_ips_with_no_events(self, time_now_str):
        ip_objects = self.ips.find()
        ip_deletion_log = open('ip_deletion_log_'+time_now_str+'.csv', 'wb')
        ip_deletion_log_writer = csv.writer(ip_deletion_log)
        ip_deletion_log_writer.writerow(['ip', 'modified', 'number_of_relationships'])
        ids_of_ips_to_remove = []
        for ip_object in ip_objects:
            has_event = False
            for relationship in ip_object['relationships']:
                if relationship['type'] == 'Event':
                    has_event = True
                    break
            if not has_event:
                number_of_relationships = len(ip_object['relationships'])
                ip_row = [ip_object['ip'], ip_object['modified'], number_of_relationships]
                ip_deletion_log_writer.writerow(ip_row)
                ids_of_ips_to_remove.append(ip_object['_id'])
        query = {
            '_id': {
                '$in': ids_of_ips_to_remove
            }
        }
        self.ips.delete_many(filter=query)
        ip_deletion_log.close()

    ### Find Functions ###

    def find_ips_ids(self):
        cursor = self.ips.find(projection={})
        ips_ids = []
        for entry in cursor:
            ips_ids.append(entry['_id'])
        return ips_ids

    def find_new_ips_ids(self):
        one_month_ago = datetime.today() - relativedelta(days=70)
        # Filter based on 'modified' date because the "old" IPs are those whose latest Event is still considered "old",
        # and IPs with new Events may have been created long before their latest Event was added.
        query = {
            'modified': {
                '$gte': one_month_ago
            }
        }
        cursor = self.ips.find(filter=query, projection={})
        ips_ids = []
        for entry in cursor:
            ips_ids.append(entry['_id'])
        return ips_ids

    def find_events_ids(self):
        cursor = self.events.find(projection={})
        events_ids = []
        for entry in cursor:
            events_ids.append(entry['_id'])
        return events_ids

    def find_new_events_ids(self):
        one_month_ago = datetime.today() - relativedelta(days=70)
        query = {
            'created': {
                '$gte': one_month_ago
            }
        }
        cursor = self.events.find(filter=query, projection={})
        events_ids = []
        for entry in cursor:
            events_ids.append(entry['_id'])
        return events_ids

    def find_ips_with_invalid_relationships(self):
        """
        Find all IPs with one or more invalid relationships.
        :return: dict
        """
        # TODO: Figure out how to make this faster. It runs very slow now when there are many IPs.
        ip_objects = self.ips.find()
        ids_of_bad_ips = []
        for ip_object in ip_objects:
            for relationship in ip_object['relationships']:
                if relationship['type'] == 'Event':
                    event_id = relationship['value']
                    event = self.events.find_one({'_id': event_id})
                    if not event:
                        ids_of_bad_ips.append(ip_object['_id'])
                        break
        query = {
            '_id': {
                '$in': ids_of_bad_ips
            }
        }
        projection = {
            'ip': 1,
            'relationships': 1
        }
        bad_ips = self.ips.find(filter=query, projection=projection)
        return bad_ips

data_purger = OldDataPurger()
data_purger.run()
