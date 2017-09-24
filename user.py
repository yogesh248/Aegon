import os
import socket
import pickle
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

host=socket.gethostbyname(socket.gethostname())
port=5000
server='localhost'
h1=SHA256.new()
h2=SHA256.new()
h2_dash=SHA256.new()

class SmartCard:
	def __init__(self,did=None,v0=None,ctr_sc=0,n=0):
		self.did=did
		self.v0=v0
		self.ctr_sc=ctr_sc
		self.n=n
	
class User:
	def __init__(self):
		self.id_u=bytearray(os.urandom(16))

	def register(self):
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.connect((server,port))
		sock.send(self.id_u)
		sc=SmartCard()
		data=sock.recv(1024)
		sc=pickle.loads(data)
		print("Enter a 16-character password:")
		pw=input()
		pw=bytearray(pw.encode())
		h1.update(bytes(pw))
		tmp1=bytearray(h1.digest())
		v=bytearray()
		for i in range(16):
			v.append(sc.v0[i]^tmp1[i])
		sc.v0=v
		sc.ctr_sc=0
		sc.n=3
		sock.close()	
		return sc

if __name__=="__main__":
	user=User()
	sc=SmartCard()
	sc=user.register()
	print("User has been registered")


			