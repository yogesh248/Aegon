import os
import socket 
import pickle
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

host='localhost'
port=5000
x=os.urandom(16)
h1=SHA256.new()
h2=SHA256.new()
h2_dash=SHA256.new()

reg_table={}

def encrypt(msg):
	iv=os.urandom(16)
	obj = AES.new(x, AES.MODE_CBC,iv)
	ct = obj.encrypt(msg)
	return ct

class SmartCard:
	def __init__(self,did=None,v0=None,ctr_sc=0,n=0):
		self.did=did
		self.v0=v0
		self.ctr_sc=ctr_sc
		self.n=n
	
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
		id=tuple(id)
		reg_table[id]=[ci,0]
		id=bytearray(id)
		return (did,v0)

	def login(self):
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.bind((host,port))
		sock.listen(1)
		conn,addr=sock.accept()
		v1=conn.recv(16)
		did=conn.recv(16)
		t1=conn.recv(16)
		conn.close()
		sock.close()
		print(v1)
		print(did)
		print(t1)	
		
if __name__=="__main__":
	server=Server()
	sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.bind((host,port))
	sock.listen(1)
	conn,addr=sock.accept()
	id_u=conn.recv(1024)
	id_u=bytearray(id_u)
	(did,v0)=server.register(id_u)
	sc=SmartCard(did,v0)
	conn.send(pickle.dumps(sc))
	conn.close()
	sock.close()
	server.login()
