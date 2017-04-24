from crits.services.core import Service

class SourceAssociaterService(Service):
    name = "source_associater_service"
    version = '0.0.1'
    template = None
    supported_types = []
    description = "A service that maps a given source to all IP addresses whose AS Number is within the list of AS Numbers of the source."

    def run(self, obj, config):
        pass