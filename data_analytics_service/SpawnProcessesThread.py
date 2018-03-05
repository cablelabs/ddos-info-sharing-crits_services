from multiprocessing import Process, Lock
from threading import Thread
import pendulum
from pymongo import MongoClient
from handlers import process_aggregate_entry


class SpawnProcessesThread(Thread):
    def __init__(self, shutdown_queue, analytics_processes_queue, remover_to_spawner_queue, bounded_semaphore):
        Thread.__init__(self)
        self.shutdown_queue = shutdown_queue
        self.analytics_processes_queue = analytics_processes_queue
        self.remover_to_spawner_queue = remover_to_spawner_queue
        self.bounded_semaphore = bounded_semaphore
        self.debug = True
        # Note: It is highly recommended to turn off performance logging in production.
        self.performance_logging = True

    def run(self):
        # Set connect=False because we're opening MongoClient before a fork, and get a warning message otherwise.
        client = MongoClient()
        staging_new_events = client.staging_crits_data.new_events
        performance_log_file_lock = Lock()
        while self.shutdown_queue.empty():
            # Group multiple entries together by their IP address to analyze all entries for a given IP at once.
            pipeline = [
                {'$limit': 4000},
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
            cursor = {'batchSize': 10}
            self.debug_message("Starting aggregation")
            aggregate_entries = staging_new_events.aggregate(pipeline, collation=collation, allowDiskUse=True, cursor=cursor)
            self.debug_message("Aggregation complete.")
            for entry in aggregate_entries:
                if not self.shutdown_queue.empty():
                    self.debug_message("Shutdown signal received while iterating over aggregation results.")
                    return
                #self.debug_message("Acquiring semaphore to add analytics process.")
                self.bounded_semaphore.acquire()
                #self.debug_message("Semaphore acquired to add analytics process.")
                args = (entry,)
                if self.performance_logging:
                    args = (entry, performance_log_file_lock)
                p = Process(target=process_aggregate_entry, args=args)
                p.start()
                #self.debug_message("Analytics process started.")
                self.analytics_processes_queue.put(p)
                #self.debug_message("Analytics process added to queue.")
            # Notify remover thread that this thread (spawner) has added last process for current round of aggregation.
            self.debug_message("Acquiring semaphore")
            self.bounded_semaphore.acquire()
            self.debug_message("Semaphore acquired to send message.")
            self.analytics_processes_queue.put("Last process started.")
            self.debug_message("Sent message")
            # Wait for previous set of processes to finish so we don't analyze any one IP with multiple processes.
            last_process_completed = False
            while True:
                #self.debug_message("Still waiting")
                if not self.shutdown_queue.empty():
                    self.debug_message("Shutdown signal received while waiting for message from remover thread.")
                    return
                # Iterate through entire queue for receiving messages in order to clear it of all messages.
                while not self.remover_to_spawner_queue.empty():
                    item = self.remover_to_spawner_queue.get()
                    if isinstance(item, basestring) and item == "Last process completed.":
                        last_process_completed = True
                if last_process_completed:
                    break
            self.debug_message("Received message")
        self.debug_message("Shutdown signal received before next aggregation query.")

    def debug_message(self, message):
        if self.debug:
            print "DEBUG: " + pendulum.now('UTC').to_rfc3339_string() + ": SpawnProcessesThread: " + message
