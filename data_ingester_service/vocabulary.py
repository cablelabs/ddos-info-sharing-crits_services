from crits.vocabulary.objects import ObjectTypes


class IngestFields:
    """
    This class defines strings representing fields used in the data ingester service.
    """
    IP_ADDRESS = 'IPaddress'
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
    # Maps each sub-object field to the 'type' of the sub-object that contains the 'value' for that field.
    API_FIELDS_TO_OBJECT_TYPES = {
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
    API_FIELDS_TO_VARIABLE_TYPES = {
        IP_ADDRESS: 'string',
        ATTACK_START_TIME: 'string',
        ATTACK_STOP_TIME: 'string',
        ATTACK_TYPES: 'array',
        TOTAL_BYTES_SENT: 'int',
        TOTAL_PACKETS_SENT: 'int',
        PEAK_BYTES_PER_SECOND: 'int',
        PEAK_PACKETS_PER_SECOND: 'int',
        SOURCE_PORT: 'int',
        DESTINATION_PORT: 'int',
        PROTOCOL: 'string'
    }

    @classmethod
    def api_field_names(cls):
        """
        Return all fields in the ingest service that are tied to an object of some Event.
        :return: list of strings
        """
        return cls.API_FIELDS_TO_VARIABLE_TYPES.keys()

    @classmethod
    def to_object_type(cls, api_field_name):
        """
        Returns the "type" of object in an Event's "objects" field whose "value" is the value of the given API field.
        :param api_field_name: The name of the field whose "type" we are returning.
        :type api_field_name: str
        :return: str
        :raise ValueError: api_field_name is not the name of a field used for Events in the API of the ingest or
        distribution service.
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
        :raise ValueError: object_type is not a type whose value is used in the API of the ingest or distribution
        service.
        """
        for api_field_name in cls.API_FIELDS_TO_OBJECT_TYPES:
            if cls.API_FIELDS_TO_OBJECT_TYPES[api_field_name] == object_type:
                return api_field_name
        raise ValueError("'" + object_type + "' is not the type of an object corresponding to a field in the service APIs.")

    @classmethod
    def api_field_to_variable_type(cls, api_field_name):
        if api_field_name not in cls.API_FIELDS_TO_VARIABLE_TYPES:
            raise ValueError("'" + api_field_name + "' is not the name of a field in the service APIs.")
        return cls.API_FIELDS_TO_VARIABLE_TYPES[api_field_name]

    @classmethod
    def object_type_to_variable_type(cls, object_type):
        api_field_name = cls.to_api_field_name(object_type)
        return cls.api_field_to_variable_type(api_field_name)
