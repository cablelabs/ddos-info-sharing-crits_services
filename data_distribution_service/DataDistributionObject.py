from mongoengine import Document, FloatField, IntField, StringField, DictField

from crits.core.crits_mongoengine import CritsDocument
from crits.vocabulary.objects import ObjectTypes


class DataDistributionObject(CritsDocument, Document):
    """
    Class to store data for GET requests.
    """
    LAST_TIME_RECEIVED = 'lastTimeReceived'
    # NUMBER_OF_TIMES_SEEN = 'numberOfTimesSeen'
    # NUMBER_OF_REPORTERS = 'numberOfReporters'
    # REPORTED_BY = 'reportedBy'
    # CITY = 'City'
    # STATE = 'State'
    # COUNTRY = 'Country'
    # LATITUDE = 'Latitude'
    # LONGITUDE = 'Longitude'
    # TOTAL_BYTES_SENT = 'totalBytesSent'
    # TOTAL_PACKETS_SENT = 'totalPacketsSent'
    # EVENTS = 'events'

    ip_address = StringField(verbose_name='IPaddress')
    # number_of_times_seen = IntField()
    # first_seen = StringField()
    # last_seen = StringField()
    # total_bps = FloatField()
    # total_pps = FloatField()
    # peak_bps = FloatField()
    # peak_pps = FloatField()
    # city = StringField()
    # state = StringField()
    # country = StringField()
    # latitude = FloatField()
    # longitude = FloatField()
    # events = DictField()