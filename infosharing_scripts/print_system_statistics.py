from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper

save_to_file = False

wrapper = MongoDBFunctionsWrapper()
print "Status of IPs:"
ip_status_count = wrapper.count_ips_by_status()
print ip_status_count

latest_date_str = "Latest date analyzed: " + wrapper.find_latest_date_ip_analyzed()
print latest_date_str

print "Unique IPs per Month:"
print wrapper.count_unique_ips_per_month()
print "Submissions per Month:"
print wrapper.count_submissions_per_month()

if save_to_file:
    for key, value in ip_status_count.iteritems():
        next_line = key + ":" + str(value)