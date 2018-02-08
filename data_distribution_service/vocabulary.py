from crits.vocabulary.objects import ObjectTypes
from data_ingester_service.vocabulary import IngestFields


class DistributionFields:
    """
    This class defines strings representing fields returned by the data distribution service.
    """
    IP_ADDRESS = IngestFields.IP_ADDRESS
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
    AGGREGATE_BYTES_PER_SECOND = 'aggregateBytesPerSecond'
    AGGREGATE_PACKETS_PER_SECOND = 'aggregatePacketsPerSecond'
    EVENTS = 'events'
    TIME_RECORDED = 'timeRecorded'
    ATTACK_START_TIME = 'attackStartTime'
    ATTACK_STOP_TIME = 'attackStopTime'
    ATTACK_TYPES = 'attackTypes'
    PEAK_BYTES_PER_SECOND = 'peakBPS'
    PEAK_PACKETS_PER_SECOND = 'peakPPS'
    SOURCE_PORT = 'sourcePort'
    DESTINATION_PORT = 'destinationPort'
    PROTOCOL = 'protocol'
    # Maps each sub-object field to the 'type' of the sub-object that contains the 'value' for that field.
    API_FIELDS_TO_OBJECT_TYPES = {
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
        TOTAL_PACKETS_SENT: ObjectTypes.TOTAL_PACKETS_SENT,
        AGGREGATE_BYTES_PER_SECOND: ObjectTypes.AGGREGATE_BYTES_PER_SECOND,
        AGGREGATE_PACKETS_PER_SECOND: ObjectTypes.AGGREGATE_PACKETS_PER_SECOND,
        ATTACK_START_TIME: ObjectTypes.ATTACK_START_TIME,
        ATTACK_STOP_TIME: ObjectTypes.ATTACK_STOP_TIME,
        ATTACK_TYPES: ObjectTypes.ATTACK_TYPE,
        PEAK_BYTES_PER_SECOND: ObjectTypes.PEAK_BYTES_PER_SECOND,
        PEAK_PACKETS_PER_SECOND: ObjectTypes.PEAK_PACKETS_PER_SECOND,
        SOURCE_PORT: ObjectTypes.SOURCE_PORT,
        DESTINATION_PORT: ObjectTypes.DEST_PORT,
        PROTOCOL: ObjectTypes.PROTOCOL
    }
    API_FIELDS_TO_VARIABLE_TYPES = {
        IP_ADDRESS: 'string',
        LAST_TIME_RECEIVED: 'string',
        NUMBER_OF_TIMES_SEEN: 'int',
        NUMBER_OF_REPORTERS: 'int',
        REPORTED_BY: 'array',
        CITY: 'string',
        STATE: 'string',
        COUNTRY: 'string',
        LATITUDE: 'float',
        LONGITUDE: 'float',
        TOTAL_BYTES_SENT: 'int',
        TOTAL_PACKETS_SENT: 'int',
        AGGREGATE_BYTES_PER_SECOND: 'int',
        AGGREGATE_PACKETS_PER_SECOND: 'int',
        TIME_RECORDED: 'string',
        ATTACK_START_TIME: 'string',
        ATTACK_STOP_TIME: 'string',
        ATTACK_TYPES: 'array',
        PEAK_BYTES_PER_SECOND: 'int',
        PEAK_PACKETS_PER_SECOND: 'int',
        SOURCE_PORT: 'int',
        DESTINATION_PORT: 'int',
        PROTOCOL: 'string'
    }
    # Indicates which fields can be found in IP addresses.
    IP_FIELDS = [
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
        AGGREGATE_BYTES_PER_SECOND,
        AGGREGATE_PACKETS_PER_SECOND,
        EVENTS
    ]
    # Indicates which fields can be found in individual Events (i.e. within objects in the EVENTS field).
    # Note how TOTAL_BYTES_SENT and TOTAL_PACKETS_SENT appear on both the IP level and the Event level.
    EVENT_FIELDS = [
        TIME_RECORDED,
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

    @classmethod
    def api_field_names(cls):
        return cls.API_FIELDS_TO_VARIABLE_TYPES.keys()

    @classmethod
    def ip_field_names(cls):
        return cls.IP_FIELDS

    @classmethod
    def event_field_names(cls):
        return cls.EVENT_FIELDS

    @classmethod
    def to_object_type(cls, api_field_name):
        """
        Returns the "type" of object in an IP's "objects" field whose "value" is the value of the given API field.
        :param api_field_name: The name of the field whose "type" we are returning.
        :type api_field_name: str
        :return: str
        :raise ValueError: api_field_name is not the name of a field in the distribution service that corresponds to
        an object type.
        """
        if api_field_name not in cls.API_FIELDS_TO_OBJECT_TYPES:
            raise ValueError("'" + api_field_name + "' is not the name of a field corresponding to an object type.")
        return cls.API_FIELDS_TO_OBJECT_TYPES[api_field_name]

    @classmethod
    def to_api_field_name(cls, object_type):
        """
        Returns the name of the API field whose value is taken from the "value" of the object in an Event's "objects"
        with the "type" specified in the parameter.
        :param object_type: The type of the object to find the API field name for.
        :type object_type: str
        :return: str
        :raise ValueError: object_type is not a type of an object that corresponds to some field in the distribution
        service.
        """
        for api_field_name in cls.API_FIELDS_TO_OBJECT_TYPES:
            if cls.API_FIELDS_TO_OBJECT_TYPES[api_field_name] == object_type:
                return api_field_name
        raise ValueError(
            "'" + object_type + "' is not the type of an object corresponding to a field in the service APIs.")

    @classmethod
    def api_field_to_variable_type(cls, api_field_name):
        if api_field_name not in cls.API_FIELDS_TO_VARIABLE_TYPES:
            raise ValueError("'" + api_field_name + "' is not the name of a field in the service APIs.")
        return cls.API_FIELDS_TO_VARIABLE_TYPES[api_field_name]

    @classmethod
    def object_type_to_variable_type(cls, object_type):
        api_field_name = cls.to_api_field_name(object_type)
        return cls.api_field_to_variable_type(api_field_name)

    @classmethod
    def is_event_field(cls, api_field_name):
        return
