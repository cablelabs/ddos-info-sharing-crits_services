from datetime import datetime
from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper

save_to_file = True
wrapper = MongoDBFunctionsWrapper()
full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
time_now = datetime.now()
time_now_str = time_now.strftime(full_time_format)


def print_quick_summary():
    # Print the number of IPs of each particular status, and total number of IPs and Events.
    global wrapper
    print "Status of IPs:"
    ip_status_count = wrapper.count_ips_by_status()
    for key, value in ip_status_count.iteritems():
        print key + ":" + str(value)
    print "Total # of IPs: " + str(wrapper.count_ips())
    print "Total # of Events: " + str(wrapper.count_events())


def print_unique_ips_per_month():
    # TODO: Figure out how I want to print or save this, if at all.
    output_lines = ["Unique IPs per Month:"]
    unique_ips_count = wrapper.count_unique_ips_per_month()
    for key, value in sorted(unique_ips_count.iteritems()):
        next_line = key + ":" + str(value)
        output_lines.append(next_line)


def print_submissions_counts():
    # Print the number of submissions during certain time periods. First count submissions per day, then per month.
    global save_to_file, wrapper, time_now_str
    period_iterations = ['day', 'month']
    for period_iteration in period_iterations:
        print 'Submissions per ' + period_iteration
        submissions_counts = wrapper.count_submissions_per_period(period=period_iteration)
        first_line = period_iteration+',IPs,Events'
        print first_line
        output_lines = [first_line]
        for period, counts in sorted(submissions_counts.iteritems()):
            ips_count = counts['ips']
            events_count = counts['events']
            next_line = period + ',' + str(ips_count) + ',' + str(events_count)
            print next_line
            output_lines.append(next_line)
        if save_to_file:
            output_lines = ['{0}\n'.format(line) for line in output_lines]
            period_submissions_file = open('submissions_per_'+period_iteration+'_'+time_now_str+'.txt', 'w')
            period_submissions_file.writelines(output_lines)
            period_submissions_file.close()


def print_ips_per_user():
    # Print the number of unique IPs submitted by each user.
    global save_to_file, wrapper, time_now_str
    first_line = "username,ips"
    print first_line
    output_lines = [first_line]
    user_ips_count = wrapper.count_ips_by_user()
    for username, value in user_ips_count.iteritems():
        next_line = username + "," + str(value)
        print next_line
        output_lines.append(next_line)
    if save_to_file:
        output_lines = ['{0}\n'.format(line) for line in output_lines]
        user_counts_file = open('ips_per_user_'+time_now_str+'.txt', 'w')
        user_counts_file.writelines(output_lines)
        user_counts_file.close()


def print_ips_by_owning_source():
    global save_to_file, wrapper, time_now_str
    first_line = "source,ips"
    print first_line
    output_lines = [first_line]
    source_ips_count = wrapper.count_ips_by_owning_source()
    for name, value in source_ips_count.iteritems():
        next_line = name + "," + str(value)
        print next_line
        output_lines.append(next_line)
    if save_to_file:
        output_lines = ['{0}\n'.format(line) for line in output_lines]
        source_counts_file = open('ips_per_owning_source_'+time_now_str+'.txt', 'w')
        source_counts_file.writelines(output_lines)
        source_counts_file.close()


print wrapper.count_events_by_attack_type()
print_quick_summary()
print_submissions_counts()
print_ips_per_user()
print_ips_by_owning_source()
