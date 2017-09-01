from datetime import datetime
from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper

save_to_file = False
wrapper = MongoDBFunctionsWrapper()
output_lines = ["Status of IPs:"]

ip_status_count = wrapper.count_ips_by_status()
for key, value in ip_status_count.iteritems():
    next_line = key + ":" + str(value)
    output_lines.append(next_line)

output_lines.append("Total # of IPs: " + str(wrapper.count_ips()))
output_lines.append("Total # of Events: " + str(wrapper.count_events()))

latest_date_str = "Latest date analyzed: " + wrapper.find_latest_date_ip_analyzed()
output_lines.append(latest_date_str)

output_lines.append("Unique IPs per Month:")
unique_ips_count = wrapper.count_unique_ips_per_month()
for key, value in sorted(unique_ips_count.iteritems()):
    next_line = key + ":" + str(value)
    output_lines.append(next_line)

output_lines.append("Submissions per Month:")
submissions_count = wrapper.count_submissions_per_month()
for month, counts in sorted(submissions_count.iteritems()):
    output_lines.append(month + ":")
    for key, value in counts.iteritems():
        next_line = key + ":" + str(value)
        output_lines.append(next_line)

output_lines.append("Unique IPs per User:")
user_ips_count = wrapper.count_ips_by_user()
for username, value in user_ips_count.iteritems():
    next_line = username + ":" + str(value)
    output_lines.append(next_line)

#TODO: print ips and events per specific day

for line in output_lines:
    print line

if save_to_file:
    full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
    time_now = datetime.now()
    time_now_str = time_now.strftime(full_time_format)
    output_file = open('output_file_'+time_now_str+'.txt', 'w')
    output_file.writelines(output_lines)
    output_file.close()
