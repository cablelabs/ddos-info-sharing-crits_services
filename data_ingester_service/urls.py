from django.conf.urls import patterns

def register_api(v1_api):
    from data_ingester_service.api import DataIngesterResource
    v1_api.register(DataIngesterResource())

urlpatterns = patterns('data_ingester_service.views',
    (r'data_ingester_query/$', 'data_ingester_query'),
    (r'get_service_data/$', 'get_service_data')
)