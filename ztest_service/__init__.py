from crits.services.core import Service
class ZTestService(Service):
    name = "dummy"
    version = "1.0.0"
    supported_types  = ['Sample']
    description = "Dummy service to do stuff."

    def run(self, obj, config):
        pass