

def register_api(v1_api):
    from data_ingester_service.api import DataIngesterResource
    v1_api.register(DataIngesterResource())

# TODO: figure out how to implement empty pattern
urlpatterns = []
