

def register_api(v1_api):
    from data_distribution_service.api import DataDistributionResource
    v1_api.register(DataDistributionResource())

# TODO: figure out how to implement empty pattern
urlpatterns = []
