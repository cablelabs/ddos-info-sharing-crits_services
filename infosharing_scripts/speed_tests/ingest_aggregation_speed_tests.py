from datetime import datetime
import os

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'

from crits.events.event import Event
from crits.ips.ip import IP
from data_ingester_service.vocabulary import IPOutputFields, EventOutputFields


class IngestAggregationSpeedTest:

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
        if self.is_events:
            self._add_aggregation_stages_start_at_events()
        else:
            self._add_aggregation_stages()
        collation = {
            'locale': 'en_US_POSIX',
            'numericOrdering': True
        }
        print "Stages:"
        for stage in self.aggregation_pipeline:
            print stage
        for i in range(0, len(self.aggregation_pipeline)):
            if i == 5:
                continue
            sub_pipeline = self.aggregation_pipeline[:(i+1)]
            print "Doing query for first " + str(i+1) + " stages..."
            if self.is_events:
                start = datetime.now()
                result = Event.objects.aggregate(*sub_pipeline, allowDiskUse=True, collation=collation, useCursor=False)
                end = datetime.now()
            else:
                start = datetime.now()
                result = IP.objects.aggregate(*sub_pipeline, allowDiskUse=True, collation=collation, useCursor=False)
                end = datetime.now()
            duration = end - start
            print "Time: " + str(duration)
            # if i >= 7:
            #     print "Converting results to list..."
            #     start = datetime.now()
            #     objects = list(result)
            #     end = datetime.now()
            #     duration = end - start
            #     print "Time to convert: " + str(duration)

    def _add_aggregation_stages(self):
        """
        Add all important stages to the aggregation pipeline.
        :return: (nothing)
        """
        # self._match_ips_on_releasability()
        # self._project_ip_sub_object_fields()
        # self._lookup_related_events()
        # self._project_event_fields_to_top_level()
        # self._group_documents_by_event_id()
        # self._project_event_fields_to_nested_level()
        # self._group_documents_by_ip_with_event_data()
        # self._project_ip_address()
        # self._project_event_fields()
        # self._add_sort_to_pipeline()
        user_organization = 'Comcast'
        # TODO: This may not be correct way to get user submitted data, so fix it.
        # Source name should definitely match user org, or else they neither submitted it nor own it.
        match_user_submissions_stage = {
            '$match': {
                'source.name': user_organization,
            }
        }
        project_cleanup_ip_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$ip',
                'relationships': 1,
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
        # NOTE: Even though we unwind 'event', there should be only one Event because the ingest service creates only
        # one relationship to any given Event.
        unwind_event_stage = {'$unwind': '$' + EVENT_FIELD}
        # Filter events based on what user submitted, since other users may have submitted events to the same IPs.
        match_event_source_stage = {
            '$match': {
                EVENT_FIELD + '.source.name': user_organization
            }
        }
        # This field is used simply to sort the data based approximately on the time the user submitted these events.
        EVENT_TIME_RECORDED_FIELD = 'eventTimeRecorded'
        attack_type_sub_object_type = EventOutputFields.get_object_type_from_field_name(EventOutputFields.ATTACK_TYPES)
        project_event_object_fields_stage = {
            '$project': {
                IPOutputFields.IP_ADDRESS: 1,
                EVENT_TIME_RECORDED_FIELD: {
                    '$dateToString': {
                        'format': '%Y-%m-%dT%H:%M:%S.%LZ',
                        'date': '$' + EVENT_FIELD + '.created'
                    }
                },
                EventOutputFields.ATTACK_TYPES: {
                    # Hopefully answers "How do I extract 'value' from each object whose type is 'Attack Type'?"
                    # TODO: now make sure this works
                    '$map': {
                        'input': {
                            '$filter': {
                                'input': '$' + EVENT_FIELD + '.objects',
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
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                sub_object_type = EventOutputFields.get_object_type_from_field_name(event_output_field)
                project_event_object_fields_stage['$project'][event_output_field] = {
                    '$let': {
                        'vars': {
                            'one_obj': {
                                '$arrayElemAt': [
                                    {
                                        '$filter': {
                                            'input': '$' + EVENT_FIELD + '.objects',
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
        sort_stage = {'$sort': {EVENT_TIME_RECORDED_FIELD: -1}}
        limit_stage = {'$limit': 20}
        self.aggregation_pipeline = [
            match_user_submissions_stage,
            project_cleanup_ip_fields_stage,
            unwind_relationships_stage,
            lookup_events_stage,
            unwind_event_stage,
            match_event_source_stage,
            project_event_object_fields_stage,
            sort_stage,
            limit_stage
        ]

    def _add_aggregation_stages_start_at_events(self):
        user_organization = 'Comcast'
        match_user_submissions_stage = {
            '$match': {
                'source.name': user_organization
            }
        }
        sort_stage = {'$sort': {'created': -1}}
        # NOTE: The next two fields we unwind should only produce one document each, because each Event should be
        # associated with exactly one IP.
        unwind_relationships_stage = {'$unwind': '$relationships'}
        IP_FIELD = 'ip_object'
        lookup_ips_stage = {
            '$lookup': {
                'from': 'ips',
                'localField': 'relationships.value',
                'foreignField': '_id',
                'as': IP_FIELD
            }
        }
        unwind_ip_field_stage = {'$unwind': '$'+IP_FIELD}
        attack_type_sub_object_type = EventOutputFields.get_object_type_from_field_name(EventOutputFields.ATTACK_TYPES)
        project_event_object_fields_stage = {
            '$project': {
                IPOutputFields.IP_ADDRESS: '$'+IP_FIELD+'.ip',
                'created': 1,
                # {
                #     '$dateToString': {
                #         'format': '%Y-%m-%dT%H:%M:%S.%LZ',
                #         'date': '$created'
                #     }
                # },
                EventOutputFields.ATTACK_TYPES: {
                    # Hopefully answers "How do I extract 'value' from each object whose type is 'Attack Type'?"
                    # TODO: now make sure this works
                    '$map': {
                        'input': {
                            '$filter': {
                                'input': '$objects',
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
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                sub_object_type = EventOutputFields.get_object_type_from_field_name(event_output_field)
                project_event_object_fields_stage['$project'][event_output_field] = {
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
        limit_stage = {'$limit': 20}
        # Note how the sort stage is done early in the query. This speeds it up significantly so it takes around
        # 30 seconds. If we put the sort right before the limit stage, the query takes 6-8 minutes.
        # (last timing with sort right before limit: 0:06:46.269706, with debug: 0:07:44.626921)
        # I believe this is because the original documents are indexed, whereas the new documents I make in intermediate
        # stages will not be indexed.
        self.aggregation_pipeline = [
            match_user_submissions_stage,
            sort_stage,
            unwind_relationships_stage,
            lookup_ips_stage,
            unwind_ip_field_stage,
            project_event_object_fields_stage,
            limit_stage
        ]

    def _match_ips_on_releasability(self):
        # Find all ips whose source includes user's organization in source, but not in relasability
        user_organization = 'Comcast'
        match_stage = {
            '$match': {
                'source.name': user_organization,
                'releasability.name': {'$ne': user_organization}
            }
        }
        self.aggregation_pipeline.append(match_stage)

    def _project_ip_sub_object_fields(self):
        """
        Adds an aggregation stage that projects the values of each IP's sub-objects to top-level fields.
        :return: (nothing)
        """
        project_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$ip',
                'relationships': 1,
            }
        }
        self.aggregation_pipeline.append(project_stage)

    def _lookup_related_events(self):
        """
        Adds stages that copy events from Events collection that are related to the given IPs.
        :return: (nothing)
        """
        unwind_relationships_stage = {'$unwind': '$relationships'}
        lookup_stage = {
            '$lookup': {
                'from': 'events',
                'localField': 'relationships.value',
                'foreignField': '_id',
                'as': 'event'
            }
        }
        unwind_event_stage = {'$unwind': '$event'}
        # NOTE: Even though we unwind 'event', we expect that there will only be one new document per each existing
        # document because of how events are tied to IPs, and we already unwinded the relationships field.
        stages = [unwind_relationships_stage, lookup_stage, unwind_event_stage]
        self.aggregation_pipeline.extend(stages)

    def _project_event_fields_to_top_level(self):
        """
        Adds stages that temporarily move fields nested in sub-objects of events to top-level fields of the documents.
        :return: (nothing)
        """
        unwind_stage = {'$unwind': '$event.objects'}
        project_stage = {
            '$project': {
                IPOutputFields.IP_ADDRESS: 1,
                'eventID': '$event._id',
                'eventtimeRecorded': {
                    '$dateToString': {
                        'format': '%Y-%m-%dT%H:%M:%S.%LZ',
                        'date': '$event.created'
                    }
                }
            }
        }
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            sub_object_type = EventOutputFields.get_object_type_from_field_name(event_output_field)
            project_stage['$project']['event' + event_output_field] = {
                '$cond': {
                    'if': {'$eq': ['$event.objects.type', sub_object_type]},
                    'then': '$event.objects.value',
                    'else': None
                }
            }
        stages = [unwind_stage, project_stage]
        self.aggregation_pipeline.extend(stages)

    def _group_documents_by_event_id(self):
        """
        Adds a stage that groups repeated documents together by the Event ID.
        :return: (nothing)
        """
        #sort_stage = {'$sort': {'eventID': 1}}
        group_stage = {
            '$group': {
                '_id': '$eventID',
                IPOutputFields.IP_ADDRESS: {'$first': '$'+IPOutputFields.IP_ADDRESS},
                'eventtimeRecorded': {'$first': '$eventtimeRecorded'},
                'eventattackTypes': {'$addToSet': '$eventattackTypes'}
            }
        }
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                group_stage['$group']['event' + event_output_field] = {'$max': '$event' + event_output_field}
        #self.aggregation_pipeline.append(sort_stage)
        self.aggregation_pipeline.append(group_stage)

    def _project_event_fields_to_nested_level(self):
        """
        Adds a stage that moves event fields into a single field named 'event'.
        :return: (nothing)
        """
        project_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: 1,
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
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            if event_output_field != EventOutputFields.ATTACK_TYPES:
                project_stage['$project']['event'][event_output_field] = '$event' + event_output_field
        self.aggregation_pipeline.append(project_stage)

    def _group_documents_by_ip_with_event_data(self):
        """
        Adds an aggregation stage that groups repeated documents together by the IP address, except that unlike the last
        time we grouped by IP, this stage adds new fields based on the events associated with the IP.
        :return: (nothing)
        """
        #sort_stage = {'$sort': {IPOutputFields.IP_ADDRESS: 1}}
        group_stage = {
            '$group': {
                '_id': '$' + IPOutputFields.IP_ADDRESS,
                'maxTimeRecorded': {'$max': '$event.timeRecorded'},
                IPOutputFields.EVENTS: {'$push': '$event'}
            }
        }
        #self.aggregation_pipeline.append(sort_stage)
        self.aggregation_pipeline.append(group_stage)

    def _project_ip_address(self):
        """
        Adds an aggregation stage that simply remaps the "_id" field to the IP address field.
        :return: (nothing)
        """
        project_ip_fields_stage = {
            '$project': {
                '_id': 0,
                IPOutputFields.IP_ADDRESS: '$_id',
                IPOutputFields.EVENTS: {
                    '$filter': {
                        'input': '$events',
                        'as': 'event',
                        'cond': {'$eq': ['$$event.timeRecorded', '$maxTimeRecorded']}
                    }
                }
            }
        }
        self.aggregation_pipeline.append(project_ip_fields_stage)

    def _project_event_fields(self):
        unwind = {'$unwind': '$events'}
        project = {
            '$project': {
                IPOutputFields.IP_ADDRESS: 1
            }
        }
        for event_output_field in EventOutputFields.SUB_OBJECT_FIELDS:
            project['$project'][event_output_field] = '$events.' + event_output_field
        stages = [unwind, project]
        self.aggregation_pipeline.extend(stages)

    def _add_sort_to_pipeline(self):
        """
        Defines the way to sort the IP addresses, and adds it to the aggregation pipeline.
        :return: (nothing)
        """
        sort_stage = {'$sort': {IPOutputFields.LAST_TIME_RECEIVED: -1}}
        self.aggregation_pipeline.append(sort_stage)


test = IngestAggregationSpeedTest()
test.run()
