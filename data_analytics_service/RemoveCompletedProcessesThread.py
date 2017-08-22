from threading import Thread


class RemoveCompletedProcessesThread(Thread):
    def __init__(self, shutdown_queue, analyzer_processes_queue, bounded_semaphore):
        Thread.__init__(self)
        self.shutdown_queue = shutdown_queue
        self.analyzer_processes_queue = analyzer_processes_queue
        self.bounded_semaphore = bounded_semaphore

    def run(self):
        while self.shutdown_queue.empty():
            if not self.analyzer_processes_queue.empty():
                front_process = self.analyzer_processes_queue.get()
                # TODO: Figure out what to use instead of is_alive(), because I don't think is_alive() is False
                # immediately when the process finishes the target function.
                if not front_process.is_alive():
                    front_process.join()
                    self.bounded_semaphore.release()
                else:
                    self.analyzer_processes_queue.put(front_process)
        # Terminate all processes in queue
        while not self.analyzer_processes_queue.empty():
            front_process = self.analyzer_processes_queue.get()
            front_process.terminate()
            front_process.join()
            self.bounded_semaphore.release()
