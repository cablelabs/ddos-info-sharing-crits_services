import Queue
import socket
from multiprocessing import BoundedSemaphore
import os
import json

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'

from SpawnProcessesThread import SpawnProcessesThread
from RemoveCompletedProcessesThread import RemoveCompletedProcessesThread


valid_senders = ["It's me you dunce!"]
password = "Let me in you knuckle head!"

# config_json_file = open('config.json')
# config_json = json.load(config_json_file)
max_number_of_processes = 10 #config_json['max_number_of_processes']

# If shutdown_queue is not empty, then it's time for the sub-threads to exit.
shutdown_queue = Queue.Queue(1)
analyzer_processes_queue = Queue.Queue(max_number_of_processes)
bounded_semaphore = BoundedSemaphore(max_number_of_processes)
spawner_thread = SpawnProcessesThread(shutdown_queue, analyzer_processes_queue, bounded_semaphore)
remover_thread = RemoveCompletedProcessesThread(shutdown_queue, analyzer_processes_queue, bounded_semaphore)

spawner_thread.start()
remover_thread.start()

# listen for signal from button press
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 9999))
server_socket.listen(5)
socket.setdefaulttimeout(60)

while True:
    try:
        conn, addr = server_socket.accept()
        data = conn.recv(1024)
        data_json = json.loads(data)
        if data_json['sender'] in valid_senders and data_json['password'] == password and data_json['command'] == 'exit':
            conn.close()
            server_socket.close()
            break
    except socket.timeout:
        pass

# Tell sub-threads to stop processing
shutdown_queue.put(True)
spawner_thread.join()
remover_thread.join()
