import os
import socket 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

host='localhost'
port=5000

class Server:
	def __init__(self):
		pass

	def register(self,id):
		backend = default_backend()
		key = os.urandom(32)
		iv = os.urandom(16)
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
		encryptor = cipher.encryptor()
		ct = encryptor.update(id) + encryptor.finalize()
		return ct	

if __name__=="__main__":
	server=Server()
	sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.bind((host,port))
	sock.listen(1)
	conn,addr=sock.accept()
	id=conn.recv(1024)
	enc=server.register(id)
	conn.send(enc)
	conn.close()
	sock.close()
