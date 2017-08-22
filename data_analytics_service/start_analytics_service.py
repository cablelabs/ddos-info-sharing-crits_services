import Queue
import socket
#from django.conf import settings
#from crits.crits import settings
#settings.configure()
from multiprocessing import BoundedSemaphore, log_to_stderr, SUBDEBUG
import os
import logging

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'

from SpawnProcessesThread import SpawnProcessesThread
from RemoveCompletedProcessesThread import RemoveCompletedProcessesThread

logger = log_to_stderr(level=SUBDEBUG)


# QUESTION: Create and possibly start thread(s) before listening, or after listening?

# If shutdown_queue is not empty, then it's time for the sub-threads to exit.
shutdown_queue = Queue.Queue(1)
max_number_of_processes = 1
analyzer_processes_queue = Queue.Queue(max_number_of_processes)
bounded_semaphore = BoundedSemaphore(max_number_of_processes)

spawner_thread = SpawnProcessesThread(shutdown_queue, analyzer_processes_queue, bounded_semaphore)
completion_thread = RemoveCompletedProcessesThread(shutdown_queue, analyzer_processes_queue, bounded_semaphore)

spawner_thread.start()
completion_thread.start()

# listen for signal from button press
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 9999))
# Create JSON structure that gets sent in message {"command": "exit" or "restart" or etc., "sender": "..."}
# create a loop on whichever is blocking
server_socket.listen(5)
conn, addr = server_socket.accept()
server_socket.close()
# Tell sub-threads to stop processing
shutdown_queue.put(True)
spawner_thread.join()
completion_thread.join()
