from crits.vocabulary.objects import ObjectTypes

class IPOutputFields:
    """
    This class defines the strings used for the names of fields returned by the distribution service at the top-level of
    an IP object.
    """
    IP_ADDRESS = 'IPaddress'
    LAST_TIME_RECEIVED = 'lastTimeReceived'
    NUMBER_OF_TIMES_SEEN = 'numberOfTimesSeen'
    NUMBER_OF_REPORTERS = 'numberOfReporters'
    REPORTED_BY = 'reportedBy'
    CITY = 'City'
    STATE = 'State'
    COUNTRY = 'Country'
    LATITUDE = 'Latitude'
    LONGITUDE = 'Longitude'
    TOTAL_BYTES_SENT = 'totalBytesSent'
    TOTAL_PACKETS_SENT = 'totalPacketsSent'
    EVENTS = 'events'
    ALL_FIELDS = [
        IP_ADDRESS,
        LAST_TIME_RECEIVED,
        NUMBER_OF_TIMES_SEEN,
        NUMBER_OF_REPORTERS,
        REPORTED_BY,
        CITY,
        STATE,
        COUNTRY,
        LATITUDE,
        LONGITUDE,
        TOTAL_BYTES_SENT,
        TOTAL_PACKETS_SENT,
        EVENTS
    ]
    # Fields whose values are found in sub-objects of the IP.
    SUB_OBJECT_FIELDS = [
        LAST_TIME_RECEIVED,
        NUMBER_OF_TIMES_SEEN,
        NUMBER_OF_REPORTERS,
        REPORTED_BY,
        CITY,
        STATE,
        COUNTRY,
        LATITUDE,
        LONGITUDE,
        TOTAL_BYTES_SENT,
        TOTAL_PACKETS_SENT
    ]
    # Maps each sub-object field to the 'type' of the sub-object that contains the 'value' for that field.
    SUB_OBJECT_FIELDS_TO_OBJECT_TYPES = {
        LAST_TIME_RECEIVED: ObjectTypes.LAST_TIME_RECEIVED,
        NUMBER_OF_TIMES_SEEN: ObjectTypes.NUMBER_OF_TIMES_SEEN,
        NUMBER_OF_REPORTERS: ObjectTypes.NUMBER_OF_REPORTERS,
        REPORTED_BY: ObjectTypes.REPORTED_BY,
        CITY: ObjectTypes.CITY,
        STATE: ObjectTypes.STATE,
        COUNTRY: ObjectTypes.COUNTRY,
        LATITUDE: ObjectTypes.LATITUDE,
        LONGITUDE: ObjectTypes.LONGITUDE,
        TOTAL_BYTES_SENT: ObjectTypes.TOTAL_BYTES_SENT,
        TOTAL_PACKETS_SENT: ObjectTypes.TOTAL_PACKETS_SENT
    }
    # Fields whose type is integer.
    INTEGER_FIELDS = [
        NUMBER_OF_TIMES_SEEN,
        NUMBER_OF_REPORTERS,
        TOTAL_BYTES_SENT,
        TOTAL_PACKETS_SENT
    ]
    # Fields whose type is float.
    FLOAT_FIELDS = [
        LATITUDE,
        LONGITUDE
    ]

    @classmethod
    def get_object_type_from_field_name(cls, field_name):
        """
        Returns the "type" of the object in an IP document's "objects" field whose "value" we would use for the field
        whose name is the input name.
        
        :param field_name: The name of the field whose type we are returning.
        :type field_name: str
        :return: str
        :raise ValueError: field_name is not a field returned by the distribution service at the top-level of an IP
        """
        if field_name not in cls.SUB_OBJECT_FIELDS_TO_OBJECT_TYPES:
            raise ValueError("'" + field_name + "' is not a sub-object field for IP objects.")
        return cls.SUB_OBJECT_FIELDS_TO_OBJECT_TYPES[field_name]


class EventOutputFields:
    ATTACK_START_TIME = 'attackStartTime'
    ATTACK_STOP_TIME = 'attackStopTime'
    TIME_RECORDED = 'timeRecorded'
    ATTACK_TYPES = 'attackTypes'
    TOTAL_BYTES_SENT = 'totalBytesSent'
    TOTAL_PACKETS_SENT = 'totalPacketsSent'
    PEAK_BYTES_PER_SECOND = 'peakBPS'
    PEAK_PACKETS_PER_SECOND = 'peakPPS'
    SOURCE_PORT = 'sourcePort'
    DESTINATION_PORT = 'destinationPort'
    PROTOCOL = 'protocol'
    ALL_EVENT_FIELDS = [
        ATTACK_START_TIME,
        ATTACK_STOP_TIME,
        TIME_RECORDED,
        ATTACK_TYPES,
        TOTAL_BYTES_SENT,
        TOTAL_PACKETS_SENT,
        PEAK_BYTES_PER_SECOND,
        PEAK_PACKETS_PER_SECOND,
        SOURCE_PORT,
        DESTINATION_PORT,
        PROTOCOL
    ]
    # Fields whose values are found in sub-objects of the Event.
    SUB_OBJECT_FIELDS = [
        ATTACK_START_TIME,
        ATTACK_STOP_TIME,
        ATTACK_TYPES,
        TOTAL_BYTES_SENT,
        TOTAL_PACKETS_SENT,
        PEAK_BYTES_PER_SECOND,
        PEAK_PACKETS_PER_SECOND,
        SOURCE_PORT,
        DESTINATION_PORT,
        PROTOCOL
    ]
    # Maps each sub-object field to the 'type' of the sub-object that contains the 'value' for that field.
    SUB_OBJECT_FIELDS_TO_OBJECT_TYPES = {
        ATTACK_START_TIME: ObjectTypes.ATTACK_START_TIME,
        ATTACK_STOP_TIME: ObjectTypes.ATTACK_STOP_TIME,
        ATTACK_TYPES: ObjectTypes.ATTACK_TYPE,
        TOTAL_BYTES_SENT: ObjectTypes.TOTAL_BYTES_SENT,
        TOTAL_PACKETS_SENT: ObjectTypes.TOTAL_PACKETS_SENT,
        PEAK_BYTES_PER_SECOND: ObjectTypes.PEAK_BYTES_PER_SECOND,
        PEAK_PACKETS_PER_SECOND: ObjectTypes.PEAK_PACKETS_PER_SECOND,
        SOURCE_PORT: ObjectTypes.SOURCE_PORT,
        DESTINATION_PORT: ObjectTypes.DEST_PORT,
        PROTOCOL: ObjectTypes.PROTOCOL
    }
    INTEGER_FIELDS = [
        TOTAL_BYTES_SENT,
        TOTAL_PACKETS_SENT,
        PEAK_BYTES_PER_SECOND,
        PEAK_PACKETS_PER_SECOND,
        SOURCE_PORT,
        DESTINATION_PORT
    ]

    @classmethod
    def get_object_type_from_field_name(cls, field_name):
        """
        Returns the "type" of the object in an Event document's "objects" field whose "value" we would use for the field
        whose name is the input name.

        :param field_name: The name of the field whose type we are returning.
        :type field_name: str
        :return: str
        :raise ValueError: field_name is not a field returned by the distribution service at the top-level of an Event
        """
        if field_name not in cls.SUB_OBJECT_FIELDS_TO_OBJECT_TYPES:
            raise ValueError("'" + field_name + "' is not a sub-object field for Event objects.")
        return cls.SUB_OBJECT_FIELDS_TO_OBJECT_TYPES[field_name]
