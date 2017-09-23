import os
import socket 
from Crypto.Cipher import AES
from Crypto.Util import number
from Crypto.Hash import SHA256

host='localhost'
port=5000
x=os.urandom(16)
p=number.getPrime(256)
h1=SHA256.new()
h2=SHA256.new()
h2_dash=SHA256.new()

def encrypt(msg):
	iv=os.urandom(16)
	obj = AES.new(x, AES.MODE_CBC,iv)
	ct = obj.encrypt(msg)
	return ct

class SmartCard:
	def __init__(self,did,v0):
		self.did=did
		self.v0=v0

class Server:
	def __init__(self):
		pass

	def register(self,id_u):
		id_s=bytearray(os.urandom(16))
		ci=bytearray(os.urandom(16))
		n0=bytearray(os.urandom(16))
		id=bytearray()
		for i in range(16):
			id.append(id_u[i]|id_s[i]|ci[i])
		tmp1=bytearray()
		for i in range(16):
			tmp1.append(id[i]|n0[i])	
		did=encrypt(bytes(tmp1))
		did=bytearray(did)
		tmp2=bytearray()
		for i in range(16):
			tmp2.append(id[i]|x[i])	
		h1.update(bytes(tmp2))
		v0=bytearray(h1.digest())
		sc=SmartCard(did,v0)
		return sc

if __name__=="__main__":
	server=Server()
	sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.bind((host,port))
	sock.listen(1)
	conn,addr=sock.accept()
	id_u=conn.recv(1024)
	id_u=bytearray(id_u)
	sc=server.register(id_u)
	conn.send(sc)
	conn.close()
	sock.close()
