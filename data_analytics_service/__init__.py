from crits.services.core import Service


class DataAnalyticsService(Service):
    name = "data_analytics_service"
    version = '0.0.1'
    template = None
    supported_types = []
    description = "A service that does a lot of things in the background, including mapping IP addresses to the ASN of the network they belong to."

    def run(self, obj, config):
        pass
