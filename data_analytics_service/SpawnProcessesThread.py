from multiprocessing import Process
from threading import Thread
from pymongo import MongoClient

from handlers import process_ip_entry


class SpawnProcessesThread(Thread):
    def __init__(self, shutdown_queue, analyzer_processes_queue, bounded_semaphore):
        Thread.__init__(self)
        self.shutdown_queue = shutdown_queue
        self.analyzer_processes_queue = analyzer_processes_queue
        self.bounded_semaphore = bounded_semaphore

    def run(self):
        # Set connect=False because we're opening MongoClient before a fork, and get a warning message otherwise.
        client = MongoClient(connect=False)
        staging_ips = client.staging_crits_data.ips
        while self.shutdown_queue.empty():
            pipeline = [
                {
                    '$group': {
                        '_id': '$IPaddress',
                        'events': {'$push': '$$ROOT'}
                    }
                }
            ]
            collation = {
                'locale': 'en_US_POSIX',
                'numericOrdering': True
            }
            aggregate_ip_entries = staging_ips.aggregate(pipeline, collation=collation, allowDiskUse=True)
            ids_of_entries_to_delete = []
            for entry in aggregate_ip_entries:
                if not self.shutdown_queue.empty():
                    return
                self.bounded_semaphore.acquire()
                p = Process(target=process_ip_entry, args=(entry,))
                p.start()
                self.analyzer_processes_queue.put(p)
                for event in entry['events']:
                    ids_of_entries_to_delete.append(event['_id'])
            # Wait for previous set of processes to finish so we don't analyze the same IP with multiple processes, and
            # so we don't delete an entry before it has been analyzed.
            while not self.analyzer_processes_queue.empty():
                if not self.shutdown_queue.empty():
                    return
            staging_ips.delete_many(filter={'_id': {'$in': ids_of_entries_to_delete}})
