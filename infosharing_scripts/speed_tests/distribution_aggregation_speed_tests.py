from datetime import datetime
import os

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'

from crits.ips.ip import IP
from data_distribution_service.vocabulary import IPOutputFields, EventOutputFields


class DistributionAggregationSpeedTest:

    def __init__(self):
        self.aggregation_pipeline = []
        self.is_events = True

    def run(self):
        """
        Returns the list of data to be sent in the 'outputData' field of a GET request.

        :param request:
        :param kwargs:
        :return: list of objects
        """
        #self._add_aggregation_stages_use_group_for_events()
        self._add_aggregation_stages_use_let_for_events()
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        print "Stages:"
        for stage in self.aggregation_pipeline:
            print stage
        for i in range(0, len(self.aggregation_pipeline)):
            sub_pipeline = self.aggregation_pipeline[:(i+1)]
            print "Doing query for first " + str(i+1) + " stages..."
            start = datetime.now()
            result = IP.objects.aggregate(*sub_pipeline, allowDiskUse=True, collation=collation, useCursor=False)
            end = datetime.now()
            duration = end - start
            print "Time: " + str(duration)
            if i >= 7:
                print "Converting results to list..."
                start = datetime.now()
                objects = list(result)
                end = datetime.now()
                duration = end - start
                print "Time to convert: " + str(duration)
                for obj in objects:
                    print obj
                    break


    def _add_aggregation_stages_use_group_for_events(self):
        match_releasability_stage = {'$match': {'releasability.name': {'$in': ['Comcast']}}}
        reported_by_sub_object_type = IPOutputFields.get_object_type_from_field_name(IPOutputFields.REPORTED_BY)
        project_ip_object_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$ip',
                'relationships': 1,
                IPOutputFields.REPORTED_BY: {
                    '$map': {
                        'input': {
                            '$filter': {
                                'input': '$objects',
                                'as': 'obj',
                                'cond': {'$eq': ['$$obj.type', reported_by_sub_object_type]}
                            }
                        },
                        'as': 'reporter_obj',
                        'in': '$$reporter_obj.value'
                    }
                }
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            if ip_output_field != IPOutputFields.REPORTED_BY:
                sub_object_type = IPOutputFields.get_object_type_from_field_name(ip_output_field)
                project_ip_object_fields_stage['$project'][ip_output_field] = {
                    '$let': {
                        'vars': {
                            'one_obj': {
                                '$arrayElemAt': [
                                    {
                                        '$filter': {
                                            'input': '$objects',
                                            'as': 'obj',
                                            'cond': {'$eq': ['$$obj.type', sub_object_type]}
                                        }
                                    },
                                    0
                                ]
                            }
                        },
                        'in': '$$one_obj.value'
                    }
                }
        unwind_relationships_stage = {'$unwind': '$relationships'}
        EVENT_FIELD = 'event'
        lookup_events_stage = {
            '$lookup': {
                'from': 'events',
                'localField': 'relationships.value',
                'foreignField': '_id',
                'as': EVENT_FIELD
            }
        }
        # NOTE: Unwinding the 'event' field should produce only one document because each relationship references one
        # specific object by its ID field.
        unwind_event_stage = {'$unwind': '$' + EVENT_FIELD}
        modified_since = '2017-06-01T00:00:00.0Z'
        modified_since_datetime = datetime.strptime(modified_since, "%Y-%m-%dT%H:%M:%S.%fZ")
        match_modified_since_stage = {'$match': {'event.created': {'$gte': modified_since_datetime}}}

        # NOTE: Below here is where it gets different from other method of aggregation.
        unwind_event_objects_stage = {'$unwind': '$'+EVENT_FIELD+'.objects'}
        project_event_fields_stage = {
            '$project': {
                IPOutputFields.IP_ADDRESS: 1,
                'eventID': '$'+EVENT_FIELD+'._id',
                'eventtimeRecorded': {
                    '$dateToString': {
                        'format': '%Y-%m-%dT%H:%M:%S.%LZ',
                        'date': '$'+EVENT_FIELD+'created'
                    }
                }
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            project_event_fields_stage['$project'][ip_output_field] = 1
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            sub_object_type = EventOutputFields.get_object_type_from_field_name(event_output_field)
            project_event_fields_stage['$project']['event' + event_output_field] = {
                '$cond': {
                    'if': {'$eq': ['$'+EVENT_FIELD+'.objects.type', sub_object_type]},
                    'then': '$'+EVENT_FIELD+'.objects.value',
                    'else': None
                }
            }
        group_by_event_stage = {
            '$group': {
                '_id': '$eventID',
                IPOutputFields.IP_ADDRESS: {'$first': '$' + IPOutputFields.IP_ADDRESS},
                'eventtimeRecorded': {'$first': '$eventtimeRecorded'},
                'eventattackTypes': {'$addToSet': '$eventattackTypes'}
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            group_by_event_stage['$group'][ip_output_field] = {'$first': '$' + ip_output_field}
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                group_by_event_stage['$group']['event' + event_output_field] = {'$max': '$event' + event_output_field}
        project_nest_event_objects_stage = {
            '$project': {
                '_id': 0,
                'IPaddress': 1,
                'event': {
                    EventOutputFields.TIME_RECORDED: '$eventtimeRecorded',
                    EventOutputFields.ATTACK_TYPES: {
                        '$filter': {
                            'input': '$eventattackTypes',
                            'as': 'attackType',
                            'cond': {'$ne': ['$$attackType', None]}
                        }
                    }
                },
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            project_nest_event_objects_stage['$project'][ip_output_field] = 1
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                project_nest_event_objects_stage['$project']['event'][event_output_field] = '$'+EVENT_FIELD+event_output_field
        group_by_ip_stage = {
            '$group': {
                '_id': '$' + IPOutputFields.IP_ADDRESS,
                IPOutputFields.EVENTS: {'$push': '$event'}
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            group_by_ip_stage['$group'][ip_output_field] = {'$first': '$' + ip_output_field}
        project_ip_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$_id',
                IPOutputFields.EVENTS: 1
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            project_ip_fields_stage['$project'][ip_output_field] = 1
        sort_stage = {'$sort': {'lastTimeReceived': -1}}
        self.aggregation_pipeline = [
            match_releasability_stage,
            project_ip_object_fields_stage,
            unwind_relationships_stage,
            lookup_events_stage,
            unwind_event_stage,
            match_modified_since_stage,
            unwind_event_objects_stage,
            project_event_fields_stage,
            group_by_event_stage,
            project_nest_event_objects_stage,
            group_by_ip_stage,
            project_ip_fields_stage,
            sort_stage
        ]

    # THE GOOD METHOD
    def _add_aggregation_stages_use_let_for_events(self):
        match_releasability_stage = {'$match': {'releasability.name': {'$in': ['Comcast']}}}
        reported_by_sub_object_type = IPOutputFields.get_object_type_from_field_name(IPOutputFields.REPORTED_BY)
        project_ip_object_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$ip',
                'relationships': 1,
                IPOutputFields.REPORTED_BY: {
                    '$map': {
                        'input': {
                            '$filter': {
                                'input': '$objects',
                                'as': 'obj',
                                'cond': {'$eq': ['$$obj.type', reported_by_sub_object_type]}
                            }
                        },
                        'as': 'reporter_obj',
                        'in': '$$reporter_obj.value'
                    }
                }
            }
        }
        modified_since = '2017-06-01T00:00:00.0Z'
        match_ip_modified_since_stage = {'$match': {IPOutputFields.LAST_TIME_RECEIVED: {'$gte': modified_since}}}
        unwind_relationships_stage = {'$unwind': '$relationships'}
        EVENT_FIELD = 'event'
        lookup_events_stage = {
            '$lookup': {
                'from': 'events',
                'localField': 'relationships.value',
                'foreignField': '_id',
                'as': EVENT_FIELD
            }
        }
        # NOTE: Unwinding the 'event' field should produce only one document because each relationship references one
        # specific object by its ID field.
        unwind_event_stage = {'$unwind': '$' + EVENT_FIELD}
        modified_since_datetime = datetime.strptime(modified_since, "%Y-%m-%dT%H:%M:%S.%fZ")
        match_modified_since_stage = {'$match': {'event.created': {'$gte': modified_since_datetime}}}
        attack_type_sub_object_type = EventOutputFields.get_object_type_from_field_name(EventOutputFields.ATTACK_TYPES)
        project_event_object_fields_stage = {
            '$project': {
                IPOutputFields.IP_ADDRESS: 1,
                EVENT_FIELD: {
                    EventOutputFields.ATTACK_TYPES: {
                        '$map': {
                            'input': {
                                '$filter': {
                                    'input': '$'+EVENT_FIELD+'.objects',
                                    'as': 'obj',
                                    'cond': {'$eq': ['$$obj.type', attack_type_sub_object_type]}
                                }
                            },
                            'as': 'reporter_obj',
                            'in': '$$reporter_obj.value'
                        }
                    }
                }
            }
        }
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                sub_object_type = EventOutputFields.get_object_type_from_field_name(event_output_field)
                project_event_object_fields_stage['$project'][EVENT_FIELD][event_output_field] = {
                    '$let': {
                        'vars': {
                            'one_obj': {
                                '$arrayElemAt': [
                                    {
                                        '$filter': {
                                            'input': '$'+EVENT_FIELD+'.objects',
                                            'as': 'obj',
                                            'cond': {'$eq': ['$$obj.type', sub_object_type]}
                                        }
                                    },
                                    0
                                ]
                            }
                        },
                        'in': '$$one_obj.value'
                    }
                }
        group_by_ip_stage = {
            '$group': {
                '_id': '$' + IPOutputFields.IP_ADDRESS,
                IPOutputFields.EVENTS: {'$push': '$event'}
            }
        }
        project_ip_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$_id',
                IPOutputFields.EVENTS: 1
            }
        }
        for ip_output_field in IPOutputFields.SUB_OBJECT_FIELDS:
            if ip_output_field != IPOutputFields.REPORTED_BY:
                sub_object_type = IPOutputFields.get_object_type_from_field_name(ip_output_field)
                project_ip_object_fields_stage['$project'][ip_output_field] = {
                    '$let': {
                        'vars': {
                            'one_obj': {
                                '$arrayElemAt': [
                                    {
                                        '$filter': {
                                            'input': '$objects',
                                            'as': 'obj',
                                            'cond': {'$eq': ['$$obj.type', sub_object_type]}
                                        }
                                    },
                                    0
                                ]
                            }
                        },
                        'in': '$$one_obj.value'
                    }
                }
            project_event_object_fields_stage['$project'][ip_output_field] = 1
            group_by_ip_stage['$group'][ip_output_field] = {'$first': '$' + ip_output_field}
            project_ip_fields_stage['$project'][ip_output_field] = 1
        sort_stage = {'$sort': {'lastTimeReceived': -1}}
        self.aggregation_pipeline = [
            match_releasability_stage,
            project_ip_object_fields_stage,
            match_ip_modified_since_stage,
            unwind_relationships_stage,
            lookup_events_stage,
            unwind_event_stage,
            match_modified_since_stage,
            project_event_object_fields_stage,
            group_by_ip_stage,
            project_ip_fields_stage,
            sort_stage
        ]

test = DistributionAggregationSpeedTest()
test.run()
