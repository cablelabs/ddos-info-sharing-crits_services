import csv
from datetime import datetime, timedelta
from multiprocessing import Pool
from pymongo import MongoClient


def remove_ith_ip_object(i):
    client = MongoClient()
    ips = client.crits.ips
    events = client.crits.events
    ip_object = ips.find_one(skip=i, sort=[('modified', 1)])
    ip_id = ip_object['_id']
    ips.delete_one({'_id': ip_id})
    for relationship in ip_object['relationships']:
        if relationship['type'] == 'Event':
            event_id = relationship['value']
            events.delete_one({'_id': event_id})


class OldDataPurger:

    def __init__(self):
        client = MongoClient()
        self.ips = client.crits.ips
        self.events = client.crits.events
        self.source_access = client.crits.source_access
        self.users = client.crits.users

    def run(self):
        # Print number of old IPs.
        time_now = datetime.now()
        # TODO: use config file for number of days
        one_month_ago = time_now - timedelta(days=30)
        old_ips_query = {'modified': {'$lt': one_month_ago}}
        count = self.ips.count(filter=old_ips_query)
        print "Number of Old IPs:", count

        # Iterate through old IPs, save their data to a log file, and delete them.
        full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        time_now_str = time_now.strftime(full_time_format)
        ip_deletion_log_filename = 'ip_deletion_log_'+time_now_str+'.csv'
        ip_deletion_log_write_file = open(ip_deletion_log_filename, 'wb')
        ip_deletion_log_writer = csv.writer(ip_deletion_log_write_file)
        ip_deletion_log_writer.writerow(['IP', 'Modified', 'AS Number'])
        old_ip_objects = self.ips.find(filter=old_ips_query)
        #number_of_ips_deleted = 0
        #number_of_ips_to_delete = 5000
        for ip_object in old_ip_objects:
            as_number = None
            for obj in ip_object['objects']:
                if obj['type'] == 'AS Number':
                    as_number = obj['value']
                    break
            ip_row = [ip_object['ip'], ip_object['modified'], as_number]
            ip_deletion_log_writer.writerow(ip_row)
            #number_of_ips_deleted += 1
            # For each of the deleted IPs, find the associated Events, and make sure none of these events
            # were created within the last 30 days. If there is an Event within 30 days, we have a bug.
            # And, assuming all Events were created outside of 30 days, delete those events.
            relationships = ip_object['relationships']
            for relationship in relationships:
                event_id = relationship['value']
                event_object = self.events.find_one({'_id': event_id})
                event_created_datetime = event_object['created']
                if event_created_datetime < one_month_ago:
                    # TODO: after testing, delete event
                    pass
                else:
                    print "DANGAR"
                    break
            #if number_of_ips_deleted >= number_of_ips_to_delete:
            #    break
            # TODO: after testing the code, delete entries
        ip_deletion_log_write_file.close()

        # Iterate through logs and make sure modified date of each IP is beyond 30 days ago.
        ip_deletion_log_read_file = open(ip_deletion_log_filename, 'rb')
        ip_deletion_log_reader = csv.reader(ip_deletion_log_read_file)
        first_row = True
        for row in ip_deletion_log_reader:
            if first_row:
                first_row = False
                continue
            modified_date = row[1]
            try:
                modified_datetime = datetime.strptime(modified_date, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                modified_datetime = datetime.strptime(modified_date, '%Y-%m-%d %H:%M:%S')
            if modified_datetime >= one_month_ago:
                print "Error"

    def delete_ips(self):
        """
        Delete half of the IPs in the database, and their corresponding events.
        :return:
        """
        number_of_ips = self.ips.count()
        number_of_events = self.events.count()
        pool = Pool(10)
        pool.map(remove_ith_ip_object, range(0, number_of_ips, 2))
        print "IPs Deleted:", number_of_ips - self.ips.count()
        print "Events Deleted:", number_of_events - self.events.count()


purger = OldDataPurger()
#purger.run()
purger.delete_ips()
