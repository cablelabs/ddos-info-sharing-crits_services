from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper

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
