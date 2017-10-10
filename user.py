import os
import socket
import pickle
import struct
from time import time
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
		v0=sc.v0
		v=bytearray()
		for i in range(16):
			v.append(sc.v0[i]^tmp1[i])
		sc.v0=v
		sc.ctr_sc=0
		sc.n=3
		sock.close()	
		return sc,v0

	def login(self,sc,v0):
		print("Enter the password:")
		pw=input()
		pw=bytearray(pw.encode())	
		if sc.ctr_sc<sc.n:
			r=bytearray(os.urandom(16))
			g=bytearray(os.urandom(16))
			e=bytearray()
			for i in range(16):
				e.append((r[i]*g[i])%256)
			tmp1=bytearray()
			t1=bytearray(struct.pack(">i",int(time())))
			for i in range(12):
				t1.append(0)
			for i in range(16):
				tmp1.append(v0[i]|self.id_u[i]|t1[i])
			h1.update(bytes(tmp1))
			tmp2=bytearray(h1.digest())
			tmp3=bytearray()
			for i in range(16):
				tmp3.append((tmp2[i]*g[i])%256)
			v1=bytearray()
			for i in range(16):
				v1.append((tmp3[i]+e[i])%256)
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(v1)
			sock.send(sc.did)
			sock.send(t1)
			sock.close()
			print(v1)
			print(sc.did)
			print(t1)

if __name__=="__main__":
	user=User()
	sc=SmartCard()
	sc,v0=user.register()
	print("User has been registered")
	user.login(sc,v0)

			