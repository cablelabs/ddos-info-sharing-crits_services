from django.core.urlresolvers import reverse

from crits.campaigns.campaign import Campaign
from crits.ips.ip import IP
from crits.ips.handlers import ip_add_update
from crits.campaigns.handlers import get_campaign_details
from crits.core.crits_mongoengine import EmbeddedCampaign
from crits.core.user_tools import user_sources
from crits.core.class_mapper import class_from_type, class_from_id

#from .__init__ import DataIngesterService

def save_incoming_data(incoming_data):

    analyst = incoming_data.get('analyst', None)
    ip = incoming_data.get('ip', None)
    name = incoming_data.get('source', None)
    reference = incoming_data.get('reference', None)
    method = incoming_data.get('method', None)
    campaign = incoming_data.get('campaign', None)
    confidence = incoming_data.get('confidence', None)
    ip_type = incoming_data.get('ip_type', None)
    add_indicator = incoming_data.get('add_indicator', False)
    indicator_reference = incoming_data.get('indicator_reference', None)
    misc = incoming_data.get('misc', None)
    bucket_list = incoming_data.get('bucket_list', None)
    ticket = incoming_data.get('ticket', None)

    result = ip_add_update(ip,
                           ip_type,
                           source=name,
                           source_method=method,
                           source_reference=reference,
                           campaign=campaign,
                           confidence=confidence,
                           analyst=analyst,
                           bucket_list=bucket_list,
                           ticket=ticket,
                           is_add_indicator=add_indicator,
                           indicator_reference=indicator_reference,
                           misc=misc)

    # add fields that IP objects don't usually have
    # ip_object = None
    #cached_results = cache.get(form_consts.IP.CACHED_RESULTS)

    #if cached_results != None:
    #    ip_object = cached_results.get(ip_address)
    #else:
    #ip_object = IP.objects(ip=ip).first()



    return
