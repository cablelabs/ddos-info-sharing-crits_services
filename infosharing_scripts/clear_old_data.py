from datetime import datetime
from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper

# TODO: How do I test the accuracy of my functions?

wrapper = MongoDBFunctionsWrapper()
print "Before:"
print wrapper.count_old_and_new_ips()
print wrapper.count_old_and_new_events()
#wrapper.remove_old_events()
#wrapper.update_event_relationships_all_ips()
#wrapper.remove_ips_with_no_events()
print "After:"
print wrapper.count_old_and_new_ips()
print wrapper.count_old_and_new_events()

full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
time_now = datetime.now()
time_now_str = time_now.strftime(full_time_format)
cron_job_file = open('cron_job_'+time_now_str+'.txt', 'w')
cron_job_file.writelines('Cron job complete.')
cron_job_file.close()
