from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper

wrapper = MongoDBFunctionsWrapper()
print "Status of IPs:"
print wrapper.count_ips_by_status()
print "Latest date analyzed: " + wrapper.find_latest_date_ip_analyzed()
print "Unique IPs per Month:"
print wrapper.count_unique_ips_per_month()
print "Submissions per Month:"
print wrapper.count_submissions_per_month()
