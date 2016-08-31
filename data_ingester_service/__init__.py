from crits.services.core import Service

class DataIngesterService(Service):
    name = "data_ingester_service"
    version = '0.0.1'
    template = None
    supported_types = []
    description = "A service that receives data from MSOs through POST messages."

    def run(self, obj, config):
        pass

    def stop(self):
        pass