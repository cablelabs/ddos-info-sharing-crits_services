from bson import json_util
import json
import pendulum
from pymongo import MongoClient
import pytz
import random
import sys
from OldDataPurger import OldDataPurger


class DataPurgerTest:
    """
    The purpose of this class is to test the functionality of purging old data from the CRITs database. The run()
    function of this class collects random samples from the IP and Event collections before running the purge functions,
    then it purges data and checks the results afterwards to make sure they're correct.
    """

    def __init__(self):
        self.sample_size = 1000
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        config_filename = '/data/configs/duration_config.json'
        with open(config_filename, 'r') as config_file:
            configs = json.load(config_file)
            months = configs['months']
            days = configs['days']
            today_datetime = pendulum.today('UTC')
            # This is the same as the datetime that would be used as the cutoff point when the purging script runs.
            self.earliest_datetime = today_datetime.subtract(months=months, days=days)
            if self.earliest_datetime is None:
                sys.exit("Error: earliest_datetime not defined.")
        self.samples_filename = 'samples_before_update.json'

    def run(self):
        self.save_random_samples()
        purger = OldDataPurger()
        purger.delete_data_before_datetime(self.earliest_datetime)
        self.check_sampled_objects()

    def save_random_samples(self):
        ips_counts = self.count_ips_before_and_after_date()
        random_ip_before_indexes = self.random_sample(range(0, ips_counts['before']), self.sample_size)
        random_ip_after_indexes = self.random_sample(range(0, ips_counts['after']), self.sample_size)
        # Collect sample of IPs created before and after the earliest datetime.
        ip_objects = self.ips.find(sort=[('modified', -1)])
        current_ips_before_index = 0
        current_ips_after_index = 0
        data_to_save = {'ips': [], 'events': []}
        for ip_object in ip_objects:
            for obj in ip_object['objects']:
                if obj['type'] == "Last Time Received":
                    last_time_received_str = obj['value']
                    last_time_received_datetime = pendulum.from_format(last_time_received_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                    simplified_ip_object = {
                        '_id': ip_object['_id'],
                        'last_time_received': last_time_received_str,
                        'relationships': ip_object['relationships']
                    }
                    if last_time_received_datetime < self.earliest_datetime:
                        if current_ips_before_index in random_ip_before_indexes:
                            data_to_save['ips'].append(simplified_ip_object)
                        current_ips_before_index += 1
                    else:
                        if current_ips_after_index in random_ip_after_indexes:
                            data_to_save['ips'].append(simplified_ip_object)
                        current_ips_after_index += 1
                    break

        # Collect sample of Events created before the earliest datetime.
        created_before_query = {'created': {'$lt': self.earliest_datetime}}
        number_of_events_before_date = self.events.count(filter=created_before_query)
        print "Number of Events before date:", number_of_events_before_date
        before_aggregation_stages = [
            {'$match': created_before_query},
            {'$sample': {'size': self.sample_size}}
        ]
        random_events_before = self.events.aggregate(before_aggregation_stages)
        for event in random_events_before:
            simplified_event = {
                '_id': event['_id'],
                'created': event['created']
            }
            data_to_save['events'].append(simplified_event)
        # Collect sample of Events created after the earliest datetime.
        created_after_query = {'created': {'$gte': self.earliest_datetime}}
        number_of_events_after_date = self.events.count(filter=created_after_query)
        print "Number of Events after date:", number_of_events_after_date
        after_aggregation_stages = [
            {'$match': created_after_query},
            {'$sample': {'size': self.sample_size}}
        ]
        random_events_after = self.events.aggregate(after_aggregation_stages)
        for event in random_events_after:
            simplified_event = {
                '_id': event['_id'],
                'created': event['created']
            }
            data_to_save['events'].append(simplified_event)

        # Save all sample data to JSON file.
        with open(self.samples_filename, 'w') as samples_file:
            json.dump(data_to_save, samples_file, default=json_util.default)

    def count_ips_before_and_after_date(self):
        # Count the number of IPs received before and after the earliest datetime.
        # Note: Might be able to calculate this value faster with aggregation query.
        number_of_ips_before_date = 0
        ip_objects = self.ips.find()
        for ip_object in ip_objects:
            for obj in ip_object['objects']:
                if obj['type'] == "Last Time Received":
                    last_time_received_str = obj['value']
                    last_time_received_datetime = pendulum.from_format(last_time_received_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                    if last_time_received_datetime < self.earliest_datetime:
                        number_of_ips_before_date += 1
        print "Number of IPs before date:", number_of_ips_before_date
        number_of_ips = self.ips.count()
        number_of_ips_after_date = number_of_ips - number_of_ips_before_date
        print "Number of IPs after date:", number_of_ips_after_date
        return {'before': number_of_ips_before_date, 'after': number_of_ips_after_date}

    @staticmethod
    def random_sample(population, k):
        # This is the same as random.sample(population, k) when len(population) >= k, but simply returns the whole
        # population if len(population) < k
        try:
            return random.sample(population, k)
        except ValueError:
            return population

    def check_sampled_objects(self):
        with open(self.samples_filename, 'r') as samples_file:
            saved_data = json.load(samples_file, object_hook=json_util.object_hook)
        ips_counts = self.count_ips_before_and_after_date()
        for saved_ip_object in saved_data['ips']:
            ip_object = self.ips.find_one(filter={'_id': saved_ip_object['_id']})
            if ip_object is None:
                # Confirm that all related Events no longer exist, and thus it was correct to remove the IP.
                for relationship in saved_ip_object['relationships']:
                    event_id = relationship['value']
                    if self.events.count(filter={'_id': event_id}) > 0:
                        print "Error: Event still exists!"
            else:
                if len(saved_ip_object['relationships']) != len(ip_object['relationships']) and \
                                ip_object['status'] != "In Progress":
                    print "Error: IP object not 'In Progress', even though some (but not all) Events have been deleted!"
                for saved_relationship in saved_ip_object['relationships']:
                    event_id = saved_relationship['value']
                    if self.events.count(filter={'_id': event_id}) > 0:
                        # Confirm that relationship still exists because Event exists.
                        found_relationship = False
                        for relationship in ip_object['relationships']:
                            relationship['relationship_date'] = relationship['relationship_date'].replace(
                                tzinfo=pytz.utc)
                            relationship['date'] = relationship['date'].replace(tzinfo=pytz.utc)
                            if self.is_relationships_equal(saved_relationship, relationship):
                                found_relationship = True
                                break
                        if not found_relationship:
                            print "Error: Relationship to Event doesn't exist when it should!"
                    else:
                        # Confirm that relationship is no longer in IP object because Event no longer exists.
                        for relationship in ip_object['relationships']:
                            relationship['relationship_date'] = relationship['relationship_date'].replace(
                                tzinfo=pytz.utc)
                            relationship['date'] = relationship['date'].replace(tzinfo=pytz.utc)
                            if self.is_relationships_equal(saved_relationship, relationship):
                                print "Error: Relationship to Event still exists when it shouldn't!"
                                break

        created_before_query = {'created': {'$lt': self.earliest_datetime}}
        number_of_events_before_date = self.events.count(filter=created_before_query)
        print "Number of Events before date:", number_of_events_before_date
        created_after_query = {'created': {'$gte': self.earliest_datetime}}
        number_of_events_after_date = self.events.count(filter=created_after_query)
        print "Number of Events after date:", number_of_events_after_date
        for saved_event in saved_data['events']:
            created = saved_event['created']
            event_object = self.events.find_one(filter={'_id': saved_event['_id']})
            if event_object is None and created >= self.earliest_datetime:
                print "Error: Event doesn't exist when created date within range!"
            elif event_object is not None and created < self.earliest_datetime:
                print "Error: Event still exists when created date outside range!"

    @staticmethod
    def is_relationships_equal(r1, r2):
        return r1['rel_confidence'] == r2['rel_confidence'] and \
               r1['relationship'] == r2['relationship'] and \
               r1['relationship_date'] == r2['relationship_date'] and \
               r1['value'] == r2['value'] and \
               r1['date'] == r2['date'] and \
               r1['type'] == r2['type'] and \
               r1['analyst'] == r2['analyst'] and \
               r1['rel_reason'] == r2['rel_reason']


test = DataPurgerTest()
test.run()
