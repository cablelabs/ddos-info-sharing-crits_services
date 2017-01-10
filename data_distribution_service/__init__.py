from crits.services.core import Service

class DataDistributionService(Service):
    name = "data_distribution_service"
    version = '0.0.1'
    template = ''
    supported_types = ['IP']
    description = "A service that sends data to ISPs that request it using GET messages."

    def run(self, obj, config):
        pass