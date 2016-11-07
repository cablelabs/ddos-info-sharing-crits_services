from django.conf.urls import patterns

urlpatterns = patterns('IP_ASN_mapping_service.views',
    (r'^ip_asn_service_screen/$', 'ip_asn_service_screen'),
    (r'^start_or_stop_service/$', 'start_or_stop_service')
)