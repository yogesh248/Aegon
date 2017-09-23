import os
import socket

host=socket.gethostbyname(socket.gethostname())
port=5000
server='localhost'

class SmartCard:
	def __init__(self,did=None,v0=None):
		self.did=did
		self.v0=v0
	
class User:
	def __init__(self):
		self.id_u=bytearray(os.urandom(16))

	def register(self):
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.connect((server,port))
		sock.send(self.id_u)
		sc=SmartCard()
		sc=sock.recv(1024)
		print(sc.did)
		print(sc.v0)
		sock.close()	


if __name__=="__main__":
	user=User()
	user.register()

			