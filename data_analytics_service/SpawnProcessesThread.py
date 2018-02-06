from multiprocessing import Process
from threading import Thread
from pymongo import MongoClient
from handlers import process_aggregate_entry


class SpawnProcessesThread(Thread):
    def __init__(self, shutdown_queue, analytics_processes_queue, remover_to_spawner_queue, bounded_semaphore):
        Thread.__init__(self)
        self.shutdown_queue = shutdown_queue
        self.analytics_processes_queue = analytics_processes_queue
        self.remover_to_spawner_queue = remover_to_spawner_queue
        self.bounded_semaphore = bounded_semaphore

    def run(self):
        # Set connect=False because we're opening MongoClient before a fork, and get a warning message otherwise.
        client = MongoClient(connect=False)
        staging_new_events = client.staging_crits_data.new_events
        while self.shutdown_queue.empty():
            # Group multiple entries together by their IP address to analyze all entries for a given IP at once.
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
            aggregate_entries = staging_new_events.aggregate(pipeline, collation=collation, allowDiskUse=True)
            for entry in aggregate_entries:
                if not self.shutdown_queue.empty():
                    return
                self.bounded_semaphore.acquire()
                p = Process(target=process_aggregate_entry, args=(entry,))
                p.start()
                self.analytics_processes_queue.put(p)
            # Notify remover thread that this thread (spawner) has added last process for current round of aggregation.
            self.bounded_semaphore.acquire()
            self.analytics_processes_queue.put("Last process started.")
            # Wait for previous set of processes to finish so we don't analyze any one IP with multiple processes.
            last_process_completed = False
            while True:
                if not self.shutdown_queue.empty():
                    return
                # Iterate through entire queue for receiving messages in order to clear it of all messages.
                while not self.remover_to_spawner_queue.empty():
                    item = self.remover_to_spawner_queue.get()
                    if isinstance(item, basestring) and item == "Last process completed.":
                        last_process_completed = True
                if last_process_completed:
                    break
