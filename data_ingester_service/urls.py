from django.conf.urls import patterns


def register_api(v1_api):
    from data_ingester_service.api import DataIngesterResource
    v1_api.register(DataIngesterResource())

urlpatterns = patterns('')
