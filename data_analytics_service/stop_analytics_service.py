import socket
import json

# "command" can also be "restart", as a future idea
message = {
    "command": "exit",
    "sender": "It's me you dunce!",
    "password": "Let me in you knuckle head!"
}
message_json_formatted_string = json.dumps(message)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 9999))
s.send(message_json_formatted_string)
s.close()
