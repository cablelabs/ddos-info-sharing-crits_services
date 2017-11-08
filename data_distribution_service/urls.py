from django.conf.urls import patterns


def register_api(v1_api):
    from data_distribution_service.api import DataDistributionResource
    v1_api.register(DataDistributionResource())

urlpatterns = patterns('')
