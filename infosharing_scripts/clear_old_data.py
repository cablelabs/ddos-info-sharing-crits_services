from datetime import datetime
from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper

# TODO: How do I test the accuracy of my functions?

wrapper = MongoDBFunctionsWrapper()
output_lines = ['Before:']
ips_counts_before = wrapper.count_old_and_new_ips()
for key, value in ips_counts_before.iteritems():
    output_lines.append(key + ':' + str(value))
events_counts_before = wrapper.count_old_and_new_events()
for key, value in events_counts_before.iteritems():
    output_lines.append(key + ':' + str(value))
#wrapper.remove_old_events()
#wrapper.update_event_relationships_all_ips()
#wrapper.remove_ips_with_no_events()
output_lines.append('After:')
ips_counts_after = wrapper.count_old_and_new_ips()
for key, value in ips_counts_after.iteritems():
    output_lines.append(key + ':' + str(value))
events_counts_after = wrapper.count_old_and_new_events()
for key, value in events_counts_after.iteritems():
    output_lines.append(key + ':' + str(value))
output_lines.append('Complete.')

for line in output_lines:
    print line

output_lines = ['{0}\n'.format(line) for line in output_lines]
full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
time_now = datetime.now()
time_now_str = time_now.strftime(full_time_format)
cron_job_file = open('clear_data_stats_'+time_now_str+'.txt', 'w')
cron_job_file.writelines(output_lines)
cron_job_file.close()
