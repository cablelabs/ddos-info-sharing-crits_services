from multiprocessing import Process
import pendulum
from threading import Thread


class RemoveCompletedProcessesThread(Thread):
    def __init__(self, shutdown_queue, analytics_processes_queue, remover_to_spawner_queue, bounded_semaphore):
        Thread.__init__(self)
        self.shutdown_queue = shutdown_queue
        self.analytics_processes_queue = analytics_processes_queue
        self.remover_to_spawner_queue = remover_to_spawner_queue
        self.bounded_semaphore = bounded_semaphore
        self.debug = False

    def run(self):
        last_process_started = False
        # Search the queue of analytics processes for the next completed process.
        while self.shutdown_queue.empty():
            #self.debug_message("Still running")
            if not self.analytics_processes_queue.empty():
                #self.debug_message("Viewing front item in analytics processes queue.")
                front_process = self.analytics_processes_queue.get()
                if isinstance(front_process, Process) and not front_process.is_alive():
                    #self.debug_message("Joining finished process.")
                    front_process.join()
                    #self.debug_message("Process joined.")
                    self.bounded_semaphore.release()
                    #self.debug_message("Semaphore released.")
                elif isinstance(front_process, basestring) and front_process == "Last process started.":
                    self.debug_message("Received message")
                    last_process_started = True
                    self.bounded_semaphore.release()
                    #self.debug_message("Semaphore released.")
                else:
                    #self.debug_message("Returning item to queue.")
                    self.analytics_processes_queue.put(front_process)
                    #self.debug_message("Item returned.")
            elif last_process_started:
                #self.debug_message("Sending message of last process completed.")
                self.remover_to_spawner_queue.put("Last process completed.")
                self.debug_message("Sent message")
                last_process_started = False
        self.debug_message("Shutdown signal received.")
        # Terminate all analytics processes.
        while not self.analytics_processes_queue.empty():
            #self.debug_message("Viewing front item in analytics process queue (during shutdown).")
            front_process = self.analytics_processes_queue.get()
            #self.debug_message("Item acquired.")
            front_process.terminate()
            #self.debug_message("Process terminated.")
            front_process.join()
            #self.debug_message("Process joined.")
            self.bounded_semaphore.release()
            #self.debug_message("Semaphore released.")

    def debug_message(self, message):
        if self.debug:
            print "DEBUG: " + pendulum.now('UTC').to_rfc3339_string() + ": RemoveCompletedProcessesThread: " + message
