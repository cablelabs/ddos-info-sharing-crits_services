from django.conf.urls import patterns

urlpatterns = patterns('IP_ASN_mapping_service.views',
    (r'^start_service_screen/$', 'start_service_screen'),
    (r'^start_service/$', 'start_service')
)