from multiprocessing import Process
from threading import Thread


class RemoveCompletedProcessesThread(Thread):
    def __init__(self, shutdown_queue, analytics_processes_queue, remover_to_spawner_queue, bounded_semaphore):
        Thread.__init__(self)
        self.shutdown_queue = shutdown_queue
        self.analytics_processes_queue = analytics_processes_queue
        self.remover_to_spawner_queue = remover_to_spawner_queue
        self.bounded_semaphore = bounded_semaphore

    def run(self):
        last_process_started = False
        # Search the queue of analytics processes for the next completed process.
        while self.shutdown_queue.empty():
            if not self.analytics_processes_queue.empty():
                front_process = self.analytics_processes_queue.get()
                if isinstance(front_process, Process) and not front_process.is_alive():
                    front_process.join()
                    self.bounded_semaphore.release()
                elif isinstance(front_process, basestring) and front_process == "Last process started.":
                    last_process_started = True
                    self.bounded_semaphore.release()
                else:
                    self.analytics_processes_queue.put(front_process)
            elif last_process_started:
                self.remover_to_spawner_queue.put("Last process completed.")
                last_process_started = False
        # Terminate all analytics processes.
        while not self.analytics_processes_queue.empty():
            front_process = self.analytics_processes_queue.get()
            front_process.terminate()
            front_process.join()
            self.bounded_semaphore.release()
