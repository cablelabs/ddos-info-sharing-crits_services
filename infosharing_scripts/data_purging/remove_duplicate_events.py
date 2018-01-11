# Remove all duplicate Events in backup directory, because there was a bug in my code where the cursor would timeout
# before deleting Events, and I backup each Event before it gets deleted.

from pymongo import MongoClient, ASCENDING

client = MongoClient()
old_events = client.old_crits_data.events

# DELETE_BATCH_SIZE = 500
# is_all_unique = False
# skip_amount = 0
# while True:
#     #event_objects = old_events.find(skip=skip_amount, limit=DELETE_BATCH_SIZE, sort=[('report_date', ASCENDING)])
#     event_objects = old_events.find(skip=skip_amount, limit=DELETE_BATCH_SIZE, sort=[('report_date', ASCENDING), ('reported_by', ASCENDING)])
#     previous_reporter = None
#     previous_report_date = None
#     # Assume all entries unique until we find duplicate.
#     is_all_unique = True
#     ids_of_events_to_delete = []
#     for event in event_objects:
#         if previous_reporter == event['reported_by'] and previous_report_date == event['report_date']:
#             is_all_unique = False
#             ids_of_events_to_delete.append(event['_id'])
#             #if len(ids_of_events_to_delete) >= DELETE_BATCH_SIZE:
#             #    break
#         if is_all_unique:
#             skip_amount += 1
#         previous_reporter = event['reported_by']
#         previous_report_date = event['report_date']
#     delete_query = {'_id': {'$in': ids_of_events_to_delete}}
#     old_events.delete_many(filter=delete_query)
#     if skip_amount > old_events.count():
#         break

# Version 2:
pipeline = [
    {
        '$group': {
            '_id': {
                'report_date': '$report_date',
                'reported_by': '$reported_by',
            },
            'ids': {'$push': '$_id'},
            'count': {'$sum': 1}
        },
    },
    {'$match': {'count': {'$gt': 1}}}
]
event_aggregation = old_events.aggregate(pipeline=pipeline, allowDiskUse=True)
ids_of_events_to_delete = []
for result in event_aggregation:
    ids = result['ids']
    # Start at index 1 instead of 0 to ignore first ID. The idea is to keep the first object and delete all others.
    for i in range(1, len(ids)):
        ids_of_events_to_delete.append(ids[i])
delete_query = {'_id': {'$in': ids_of_events_to_delete}}
old_events.delete_many(filter=delete_query)
