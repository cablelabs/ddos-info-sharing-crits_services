from django.conf import settings
from crits.core.mongo_tools import mongo_connector
from crits.core.class_mapper import class_from_id
from crits.core.handlers import collect_objects
from crits.backdoors.backdoor import Backdoor
from crits.emails.email import Email
from crits.samples.sample import Sample
from crits.indicators.indicator import Indicator
from crits.ips.ip import IP
from crits.domains.domain import Domain
from crits.events.event import Event
from crits.vocabulary.objects import ObjectTypes

def execute_data_get(sources):
    data = {'info': 'qwerty'}
    return data