from mongoengine import Document, FloatField, IntField, StringField, DictField, ListField

from crits.core.crits_mongoengine import CritsDocument
from crits.vocabulary.objects import ObjectTypes


class DataDistributionObject(CritsDocument, Document):
    """
    Class to store data for GET requests.
    """
    IPaddress = StringField()
    lastTimeReceived = StringField()
    numberOfTimesSeen = IntField()
    numberOfReporters = IntField()
    reportedBy = ListField(StringField)
    City = StringField()
    State = StringField()
    Country = StringField()
    Latitude = FloatField()
    Longitude = FloatField()
    totalBytesSent = IntField()
    totalPacketsSent = IntField()
    events = DictField()
