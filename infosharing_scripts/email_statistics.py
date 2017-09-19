from datetime import datetime
from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper
import csv

wrapper = MongoDBFunctionsWrapper()
full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
time_now = datetime.now()
time_now_str = time_now.strftime(full_time_format)

csv_file = open('global_statistics_'+time_now_str+'.csv', 'wb')
stats_writer = csv.writer(csv_file)
stats_writer.writerow(['Statistic', 'Value'])

total_ips = wrapper.count_ips()
stats_writer.writerow(['Total # of IPs', total_ips])
total_events = wrapper.count_events()
stats_writer.writerow(['Total # of Events', total_events])
event_type_counts = wrapper.count_events_by_attack_type()
# TODO: how many "top types of attacks" do we want? Just the highest? The 2 or 3 highest? More?
top_attack_type = max(event_type_counts, key=lambda k: event_type_counts[k])
stats_writer.writerow(['Top Attack Type', top_attack_type])
number_ips_reported_by_many_sources = wrapper.count_ips_reported_by_multiple_sources()
stats_writer.writerow(['Number of IPs reported by more than one data provider', number_ips_reported_by_many_sources])


# TODO: create text file for each user, then send data to them.
# Their files include: number of submissions from that user, ...

# TODO: email data to users

csv_file.close()
