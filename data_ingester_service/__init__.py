from crits.services.core import Service


class DataIngesterService(Service):
    name = "data_ingester_service"
    version = '0.0.1'
    template = ''
    supported_types = ['IP']
    description = "A service that receives data from ISPs through POST messages."

    def run(self, obj, config):
        pass
