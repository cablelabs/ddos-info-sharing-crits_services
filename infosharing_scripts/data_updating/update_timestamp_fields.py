"""
Note: Before running script the first time, set status of each IP and Event object to "In Progress", and set the
timezone of CRITs to UTC.

The purpose of this script is to update any timestamp fields that originally used the current time in the server's
local timezone (MST). The values will be converted to UTC. These are the fields to update for each object:
IP: created, modified, Last Time Received
Event: created, modified

When new values are saved to an object, the 'modified' time of that object will be set to a legitimate UTC time
(specifically the time when the values were saved).
"""
from datetime import datetime
import re
import pytz
from tzlocal import get_localzone
from pymongo import MongoClient
import pendulum


class UpdateTimestampFields:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events

    def run(self):
        print "Script Start (UTC):", pendulum.now('UTC')
        self.update_ips()
        self.update_events()

    def update_ips(self):
        ip_objects = self.ips.find(filter={'status': 'In Progress'})
        number_of_ips = 0
        start_time = datetime.now()
        for ip_object in ip_objects:
            new_created_date = self.local_time_to_utc(ip_object['created'])
            new_relationships = self.updated_relationships(ip_object)
            new_sources = self.updated_sources(ip_object)
            new_objects = self.updated_objects(ip_object)
            query = {'_id': ip_object['_id']}
            update_operators = {
                '$set': {
                    'created': new_created_date,
                    'modified': pendulum.now('UTC'),
                    'status': 'Analyzed',
                    'relationships': new_relationships,
                    'source': new_sources,
                    'objects': new_objects
                }
            }
            self.ips.update_one(filter=query, update=update_operators)
            number_of_ips += 1
        duration = datetime.now() - start_time
        print "Time to update IPs:", duration
        print "Number of IPs:", number_of_ips

    def update_events(self):
        event_objects = self.events.find(filter={'status': 'In Progress'})
        number_of_events = 0
        start_time = datetime.now()
        for event_object in event_objects:
            new_created_date = self.local_time_to_utc(event_object['created'])
            new_relationships = self.updated_relationships(event_object)
            new_sources = self.updated_sources(event_object)
            new_objects = self.updated_objects(event_object)
            query = {'_id': event_object['_id']}
            update_operators = {
                '$set': {
                    'created': new_created_date,
                    'modified': pendulum.now('UTC'),
                    'status': 'New',
                    'title': self.new_title(event_object['title']),
                    'relationships': new_relationships,
                    'source': new_sources,
                    'objects': new_objects
                }
            }
            self.events.update_one(filter=query, update=update_operators)
            number_of_events += 1
        duration = datetime.now() - start_time
        print "Time to update Events:", duration
        print "Number of Events:", number_of_events

    def new_title(self, title):
        timestamp_string = self.timestamp_str_from_title(title)
        try:
            timestamp_datetime = datetime.strptime(timestamp_string, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            return title
        timestamp_datetime = self.local_time_to_utc(timestamp_datetime)
        new_timestamp_string = timestamp_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        title_split = title.split('Time')
        title_prefix = title_split[0]
        new_title = title_prefix + 'Time:[' + new_timestamp_string + ']'
        return new_title

    @staticmethod
    def timestamp_str_from_title(title):
        # Extract timestamp string from input title of some Event object
        search_query = "Time:\[.*\]"
        results = re.findall(search_query, title)
        main_result = results[0]
        split1 = main_result.split('Time:[')
        main_result = filter(None, split1)[0]
        split2 = main_result.split(']')
        main_result = filter(None, split2)[0]
        return main_result

    def updated_relationships(self, document):
        new_relationships = []
        for relationship in document['relationships']:
            relationship['relationship_date'] = self.local_time_to_utc(relationship['relationship_date'])
            relationship['date'] = self.local_time_to_utc(relationship['date'])
            new_relationships.append(relationship)
        return new_relationships

    def updated_sources(self, document):
        # Update "date" of each "instance" of each "source" of overall document.
        new_sources = []
        for src in document['source']:
            new_instances = []
            for instance in src['instances']:
                instance['date'] = self.local_time_to_utc(instance['date'])
                new_instances.append(instance)
            src['instances'] = new_instances
            new_sources.append(src)
        return new_sources

    def updated_objects(self, document):
        """
        Created new versions of all objects of given Document, with all timestamp fields updated.
        :param document: The Document to update.
        :return:
        """
        new_objects = []
        for obj in document['objects']:
            obj['date'] = self.local_time_to_utc(obj['date'])
            # Update "date" of each "instance" of each "source" of current object.
            new_sources = []
            for src in obj['source']:
                new_instances = []
                for instance in src['instances']:
                    instance['date'] = self.local_time_to_utc(instance['date'])
                    new_instances.append(instance)
                src['instances'] = new_instances
                new_sources.append(src)
                obj['source'] = new_sources
            # Update values of timestamp objects.
            if obj['type'] == 'Last Time Received':
                last_time_seen = obj['value']
                last_time_seen_datetime = None
                try:
                    last_time_seen_datetime = datetime.strptime(last_time_seen, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    pass
                if last_time_seen_datetime:
                    last_time_seen_datetime = self.local_time_to_utc(last_time_seen_datetime)
                    new_last_time_seen = last_time_seen_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    obj['value'] = new_last_time_seen
            elif obj['type'] == 'Attack Start Time' or obj['type'] == 'Attack Stop Time':
                # Add "Z" to the end if there is no timezone, and replace lowercase "z" with uppercase "Z".
                attack_time = obj['value']
                attack_time_split = attack_time.split('z')
                attack_time = filter(None, attack_time_split)[0]
                if "Z" not in attack_time:
                    attack_time += "Z"
                    obj['value'] = attack_time
            new_objects.append(obj)
        return new_objects

    @staticmethod
    def local_time_to_utc(local_datetime):
        """
        Return the UTC time equivalent to the input local datetime.
        :param local_datetime: datetime object
        :return: datetime object
        """
        local_timezone = get_localzone()
        localized_time = local_timezone.localize(local_datetime)
        utc_time = localized_time.astimezone(pytz.utc)
        return utc_time


update = UpdateTimestampFields()
update.run()
