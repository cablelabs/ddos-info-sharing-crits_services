from datetime import datetime, timedelta
from pymongo import MongoClient

client = MongoClient()
events = client.crits.events
ips = client.crits.ips
users = client.crits.users
full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
time_now = datetime.now()
time_now_str = time_now.strftime(full_time_format)

# Part 1: Create file to count total amount of data submitted.

can_write_file = True
if can_write_file:
    output_file = open('output_file_'+time_now_str+'.txt', 'w')

    for user in users.find():
        username = user['username']
        count = ips.count({'source.instances.analyst': username})
        output_file.write("Number of Unique IPs from user '" + username + "': " + str(count) + "\n")

    total_event_count = events.count()
    total_ip_count = ips.count()
    output_file.write("Number of IPs: " + str(total_ip_count) + "\n")
    output_file.write("Number of Events: " + str(total_event_count))
    output_file.close()


# Part 2: Create a file to count the number of IPs submitted each day up to now.

event_count_per_day_file = open('day_counts_'+time_now_str+'.txt', 'w')
start_day = datetime(year=2017, month=6, day=1)
current_day = start_day
while current_day < time_now:
    # Calculate the day's end as start of next day
    current_day_end = current_day + timedelta(days=1)
    print 'Start:' + current_day.strftime(full_time_format) + ',End:' + current_day_end.strftime(full_time_format)
    # unwind1 = {'$unwind': '$source'}
    # unwind2 = {'$unwind': '$source.instances'}
    # match = {
    #     '$match': {
    #         'source.instances.date': {
    #             '$gte': current_day,
    #             '$lt': current_day_end
    #         }
    #     }
    # }
    # count = {'$count': 'number_of_ips'}
    # pipeline = [unwind1, unwind2, match, count]
    # ip_objects_count_obj = ips.aggregate(pipeline, allowDiskUse=True)
    # ip_objects_count_list = list(ip_objects_count_obj)
    # if ip_objects_count_list:
    #     info_str = current_day.strftime('%Y-%m-%d')+','+str(ip_objects_count_list[0]['number_of_ips'])
    # else:
    #     info_str = current_day.strftime('%Y-%m-%d')+',0'
    query = {
        'created': {
            '$gte': current_day,
            '$lt': current_day_end
        }
    }
    event_count = events.count(query)
    info_str = current_day.strftime('%Y-%m-%d') + ',' + str(event_count)
    print info_str
    event_count_per_day_file.write(info_str+'\n')
    current_day += timedelta(days=1)

event_count_per_day_file.close()
