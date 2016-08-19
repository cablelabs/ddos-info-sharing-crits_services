from crits.services.core import Service, AnalysisTask
from crits.services.analysis_result import AnalysisResult, AnalysisConfig
from crits.services.handlers import add_task


from collections import defaultdict
import weakref

class DataIngesterService(Service):
    name = "data_ingester_service"
    version = '0.0.1'
    template = None
    supported_types = []
    description = "Ingest data."

    #instances = []
    #_instances = set()
    #__refs__ = defaultdict(list)

    #def __init__(self, *args, **kwargs):
        #self.__class__.instances.append(weakref.proxy(self))
        #self._instances = set()
        #DataIngesterService._instances.add(self)

        #self.shelve_file = shelve.open("/home/infosharing/Documents/Storage")
        #self.shelve_file["service_object"] = self
        #DataIngesterService.__refs__[self.__class__].append(weakref.ref(self))
        #a = 1

    def run(self, obj, config):
        task = AnalysisTask(None, None, 'admin3')
        task.config = AnalysisConfig()
        task.start()
        add_task(task)
        self._add_result("Extra Data", "Extra data for an IP object.",
                         data=config)
        pass

    def stop(self):
        pass

    #@classmethod
    #def get_instances(cls):
    #    for inst_ref in cls.__refs[cls]:
    #        inst = inst_ref()
    #        if inst is not None:
    #            yield inst

    #def getinstances(cls):
        #dead = set()
        #for ref in DataIngesterService._instances:
        #    obj = ref()
        #    if obj is not None:
        #        yield obj
        #    else:
        #        dead.add(ref)
        #DataIngesterService._instances -= dead
        #return DataIngesterService._instances