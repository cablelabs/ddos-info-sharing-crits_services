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


# If shutdown_queue is not empty, then it's time for the sub-threads to exit.
config_json_file = open('config.json')
config_json = json.load(config_json_file)
max_number_of_processes = config_json['max_number_of_processes']
# This determines what the thread should iterate over when assigning jobs to processes.
# 'oplog' means look at the entries in the oplog.rs collection. 'ips' means to do every IP address.
iteration_unit = config_json['iteration_unit']

shutdown_queue = Queue.Queue(1)
analyzer_processes_queue = Queue.Queue(max_number_of_processes)
bounded_semaphore = BoundedSemaphore(max_number_of_processes)
spawner_thread = SpawnProcessesThread(shutdown_queue, analyzer_processes_queue, bounded_semaphore, iteration_unit)
remover_thread = RemoveCompletedProcessesThread(shutdown_queue, analyzer_processes_queue, bounded_semaphore)

spawner_thread.start()
remover_thread.start()

# listen for signal from button press
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 9999))
server_socket.listen(5)
conn, addr = server_socket.accept()
server_socket.close()
while True:
    data = conn.recv(1024)
    data_json = json.loads(data)
    if data_json['sender'] in valid_senders and data_json['password'] == password and data_json['command'] == 'exit':
        break

conn.close()
# Tell sub-threads to stop processing
shutdown_queue.put(True)
spawner_thread.join()
remover_thread.join()
