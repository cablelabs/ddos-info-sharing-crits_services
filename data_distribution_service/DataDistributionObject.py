from mongoengine import Document, FloatField, IntField, StringField

from crits.core.crits_mongoengine import CritsDocument
from crits.vocabulary.objects import ObjectTypes


class DataDistributionObject(CritsDocument, Document):
    """
    Class to store data for GET requests.
    """
    ip_address = StringField(verbose_name='IPaddress')
    number_of_times = IntField()
    first_seen = StringField()
    last_seen = StringField()
    total_bps = FloatField()
    total_pps = FloatField()
    peak_bps = FloatField()
    peak_pps = FloatField()
    city = StringField()
    state = StringField()
    country = StringField()
    latitude = FloatField()
    longitude = FloatField()
    attack_types = StringField()

    variable_name_to_output_field = {
        'ip_address': 'IPaddress',
        'number_of_times': 'numberOfTimesSeen',
        'first_seen': 'firstTimeSeen',
        'last_seen': 'lastTimeSeen',
        'total_bps': 'totalBPS',
        'total_pps': 'totalPPS',
        'peak_bps': 'peakBPS',
        'peak_pps': 'peakPPS',
        'city': 'City',
        'state': 'State',
        'country': 'Country',
        'latitude': 'Latitude',
        'longitude': 'Longitude',
        'attack_types': 'attackTypes'
    }

    @classmethod
    def get_all_variable_names(cls):
        return cls.variable_name_to_output_field.keys()

    @classmethod
    def get_output_field_from_variable_name(cls, variable_name):
        if variable_name not in cls.variable_name_to_output_field:
            return None
        return cls.variable_name_to_output_field[variable_name]

    @classmethod
    def get_variable_name_from_output_field(cls, output_field_param):
        for variable_name, output_field in cls.variable_name_to_output_field.items():
            if output_field == output_field_param:
                return variable_name
        return None

    output_field_to_object_type = {
        'numberOfTimesSeen': ObjectTypes.NUMBER_OF_TIMES_SEEN,
        'firstTimeSeen': ObjectTypes.TIME_FIRST_SEEN,
        'lastTimeSeen': ObjectTypes.TIME_LAST_SEEN,
        'totalBPS': ObjectTypes.TOTAL_BYTES_PER_SECOND,
        'totalPPS': ObjectTypes.TOTAL_PACKETS_PER_SECOND,
        'peakBPS': '',
        'peakPPS': '',
        'City': ObjectTypes.CITY,
        'State': ObjectTypes.STATE,
        'Country': ObjectTypes.COUNTRY,
        'attackTypes': ObjectTypes.ATTACK_TYPE
    }

    @classmethod
    def get_all_output_fields(cls):
        return cls.output_field_to_object_type.keys()

    @classmethod
    def get_object_type_from_variable_name(cls, variable_name):
        output_field = cls.get_output_field_from_variable_name(variable_name)
        if output_field and output_field in cls.output_field_to_object_type:
            return cls.output_field_to_object_type[output_field]
        return None

    @classmethod
    def get_object_type_from_output_field(cls, output_field):
        if output_field in cls.output_field_to_object_type:
            return cls.output_field_to_object_type[output_field]
        return None