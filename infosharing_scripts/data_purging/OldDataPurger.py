import csv
import pendulum
from multiprocessing import Pool
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError


def retrieve_ith_ip_address(i):
    client = MongoClient()
    ips = client.crits.ips
    ip_object = ips.find_one(skip=i, sort=[('modified', 1)])
    return ip_object['ip']


def remove_ip_object(ip_address):
    client = MongoClient()
    ips = client.crits.ips
    events = client.crits.events
    ip_object = ips.find_one(filter={'ip': ip_address})
    try:
        ip_id = ip_object['_id']
        ips.delete_one({'_id': ip_id})
        for relationship in ip_object['relationships']:
            if relationship['type'] == 'Event':
                event_id = relationship['value']
                events.delete_one({'_id': event_id})
    except TypeError as e:
        print e.message


class OldDataPurger:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users
        self.old_ips = client.old_crits_data.ips
        self.old_events = client.old_crits_data.events

    def delete_data_before_datetime(self, earliest_datetime):
        """
        Delete all data submitted before the input datetime.
        :param earliest_datetime: The datetime such that all data submitted before this time will be deleted.
        :type earliest_datetime: datetime
        :return: (nothing)
        """
        self.delete_old_data_sequential(earliest_datetime)
        return

    def delete_old_data_sequential(self, earliest_datetime):
        """
        Delete all data submitted before the input datetime, using sequential methods.
        :param earliest_datetime: The datetime such that all data submitted before this time will be deleted.
        :type earliest_datetime: datetime
        :return: (nothing)
        """
        self.delete_old_data_sequential_v2(earliest_datetime)

    def delete_old_data_sequential_v1(self, earliest_datetime):
        """
        In this version, first delete all IPs whose most recent submission is before the input datetime.
        Then remove all Events associated with those IPs.
        :param earliest_datetime: The datetime such that all data submitted before this time will be deleted.
        :type earliest_datetime: datetime
        :return: (nothing)
        """
        self.delete_old_ips_sequential(earliest_datetime)

    def delete_old_ips_sequential(self, earliest_datetime):
        """
        Delete all IPs whose most recent submission is before the input datetime.
        :param earliest_datetime: The datetime used to determine which IPs to delete.
        :type earliest_datetime: datetime
        :return: (nothing)
        """
        start_time = pendulum.now()
        ip_objects = self.ips.find()
        for ip_object in ip_objects:
            ip_address = ip_object['ip']
            for obj in ip_object['objects']:
                if obj['type'] == "Last Time Received":
                    last_time_received_str = obj['value']
                    last_time_received_datetime = pendulum.from_format(last_time_received_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                    if last_time_received_datetime < earliest_datetime:
                        if self.old_ips.count(filter={'ip': ip_address}) <= 0:
                            archive_ip_object = {'ip': ip_address}
                            self.old_ips.insert_one(archive_ip_object)
                        for relationship in ip_object['relationships']:
                            event_id_query = {'_id': relationship['value']}
                            event_object = self.events.find_one(filter=event_id_query)
                            if event_object is not None:
                                # Note: We expect the Event to have exactly one source.
                                for src in event_object['source']:
                                    archive_event_object = {
                                        'report_date': event_object['created'],
                                        'reported_by': src['name']
                                    }
                                    self.old_events.insert_one(archive_event_object)
                                self.events.delete_one(filter=event_id_query)
                        self.ips.delete_one(filter={'_id': ip_object['_id']})
                        break
        duration = pendulum.now() - start_time
        print "Time to delete IPs, sequential:", duration

    # PROBABLY WON'T BE USED
    def delete_unassociated_events_sequential(self):
        """
        Delete all Events that are not associated with a valid IP. A valid IP means the IP still exists in the database.
        Iterate through Events sequentially.
        :return: (nothing)
        """
        start_time = pendulum.now()
        event_objects = self.events.find()
        for event_object in event_objects:
            # Note: We expect the Event object to have exactly one relationship.
            for relationship in event_object['relationships']:
                ip_id = relationship['value']
                ip_object = self.ips.find_one(filter={'_id': ip_id})
                if ip_object is None:
                    # Note: We expect the Event to have exactly one source.
                    for src in event_object['source']:
                        archive_event_object = {
                            'report_date': event_object['created'],
                            'reported_by': src['name']
                        }
                        self.old_events.insert_one(archive_event_object)
                    self.events.delete_one(filter={'_id': event_object['_id']})
        duration = pendulum.now() - start_time
        print "Time to delete Events, sequential:", duration

    def delete_old_data_sequential_v2(self, earliest_datetime):
        """
        In this version, first delete all Events submitted before the input datetime. Then remove IPs that have no
        existing Events, and also remove relationships within IPs to Events that don't exist.
        :param earliest_datetime: The datetime such that all data submitted before this time will be deleted.
        :type earliest_datetime: datetime
        :return: (nothing)
        """
        self.delete_old_events_sequential(earliest_datetime)

    def delete_old_events_sequential(self, earliest_datetime):
        """
        Delete all Events submitted before the input datetime.
        :param earliest_datetime: The datetime used to determine which Events to delete.
        :type earliest_datetime: datetime
        :return: (nothing)
        """
        start_time = pendulum.now()
        query = {'created': {'$lt': earliest_datetime}}
        event_objects = self.events.find(filter=query)
        ids_of_ips_to_reanalyze = []
        for event_object in event_objects:
            # Archive the Event object.
            # Note: We expect the Event to have exactly one source.
            for src in event_object['source']:
                archive_event_object = {
                    'report_date': event_object['created'],
                    'reported_by': src['name']
                }
                self.old_events.insert_one(archive_event_object)
            # Note: We expect the Event object to have exactly one relationship.
            for relationship in event_object['relationships']:
                ip_id = relationship['value']
                ip_id_query = {'_id': ip_id}
                if self.ips.count(filter=ip_id_query) == 1:
                    update = {'$pull': {'relationships': {'value': event_object['_id']}}}
                    self.ips.update_one(filter=ip_id_query, update=update)
                    if ip_id not in ids_of_ips_to_reanalyze:
                        ids_of_ips_to_reanalyze.append(ip_id)
                    ip_object = self.ips.find_one(filter=ip_id_query)
                    if ip_object is not None and len(ip_object['relationships']) == 0:
                        # Archive the IP object and delete it.
                        archive_ip_object = {'ip': ip_object['ip']}
                        if self.old_ips.count(filter=archive_ip_object) <= 0:
                            self.old_ips.insert_one(archive_ip_object)
                        self.ips.delete_one(filter=ip_id_query)
                        ids_of_ips_to_reanalyze.remove(ip_id)
        duration = pendulum.now() - start_time
        print "Time to archive Events and IPs:", duration
        start_time = pendulum.now()
        self.events.delete_many(filter=query)
        duration = pendulum.now() - start_time
        print "Time to delete Events, sequential:", duration
        # Set status of IPs that had Events removed to "In Progress" so analytics service re-runs on those IPs.
        ip_ids_query = {'_id': {'$in': ids_of_ips_to_reanalyze}}
        ip_status_update = {'$set': {'status': 'In Progress'}}
        self.ips.update_many(filter=ip_ids_query, update=ip_status_update)
        return

    # PROBABLY WON'T BE USED
    def update_ips_sequential(self):
        start_time = pendulum.now()
        ip_objects = self.ips.find()
        ids_of_ips_to_reanalyze = []
        for ip_object in ip_objects:
            # IDs of relationships to remove, because the Event they were associated with no longer exists.
            ids_of_relationships_to_remove = []
            for relationship in ip_object['relationships']:
                if relationship['type'] == 'Event':
                    event_id = relationship['value']
                    event = self.events.find_one({'_id': event_id})
                    if not event:
                        ids_of_relationships_to_remove.append(relationship['_id'])
            ip_query = {'_id': ip_object['_id']}
            if len(ip_object['relationships']) == len(ids_of_relationships_to_remove):
                # All Events tied to IP were removed, so remove the IP as well.
                self.ips.delete_one(filter=ip_query)
            else:
                update = {'$pull': {'relationships.id': {'$in': ids_of_relationships_to_remove}}}
                self.ips.update_one(filter=ip_query, update=update)
                ids_of_ips_to_reanalyze.append(ip_object['_id'])
        # TODO: Redo analytics on IPs that had events removed. Ideally, IPs with no Events were already deleted.
        for ip_id in ids_of_ips_to_reanalyze:
            pass
        duration = pendulum.now() - start_time
        print "Time to update IPs, sequential:", duration
        return
