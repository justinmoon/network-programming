# Ex 1: Ping-Pong

import socket

sock = socket.socket()
sock.connect(("68.183.109.101", 10000))
sock.send(b"ping")
response = sock.recv(1024)
print("Response: ", response)
