import os
import socket 
import pickle
import struct
import sys
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

host='localhost'
port=5000
x=os.urandom(32)
iv=os.urandom(16)
h1=SHA256.new()
h2=SHA256.new()
h2_dash=SHA256.new()
rt,rctr,lt,lctr,pt,pctr,st,sctr=0,0,0,0,0,0,0,0
rbw,lbw,pbw,sbw=0,0,0,0
reg_table={}

def encrypt(msg):
	obj = AES.new(x, AES.MODE_CBC,iv)
	ct = obj.encrypt(msg)
	return ct

def decrypt(ct):	
	obj = AES.new(x, AES.MODE_CBC,iv)
	msg=obj.decrypt(ct)
	return msg

class SmartCard:
	def __init__(self,did=None,v0=None,ctr_sc=0,n=3):
		self.did=did
		self.v0=v0
		self.ctr_sc=ctr_sc
		self.n=n
	def increment_counter(self):
		self.ctr_sc=self.ctr_sc+1

class Server:
	def __init__(self):
		pass

	def register(self,id_u):
		global rt,rctr
		r_start=time.clock()
		id_s=bytearray(os.urandom(32))
		ci=bytearray(os.urandom(32))
		n0=bytearray(os.urandom(32))
		id=bytearray()
		for i in range(32):
			id.append(id_u[i]|id_s[i]|ci[i])
		tmp1=bytearray()
		for i in range(32):
			tmp1.append(id[i]|n0[i])		
		did=encrypt(bytes(tmp1))
		did=bytearray(did)
		tmp2=bytearray()
		for i in range(32):
			tmp2.append(id[i]|x[i])	
		h1.update(bytes(tmp2))
		v0=bytearray(h1.digest())
		id=tuple(id)
		reg_table[id]=[ci,0]
		id=bytearray(id)
		r_end=time.clock()
		rt=rt+(r_end-r_start)
		rctr=rctr+1
		return (did,v0,tmp1,id,id_s)

	def authenticate(self,sk):
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.bind((host,port))
		sock.listen(1)
		conn,addr=sock.accept()
		flg=conn.recv(1).decode()
		conn.close()
		sock.close()
		if flg=='1':
			print("The session key is {0}".format(sk))
			return 1
		else:
			reg_table[id][1]=reg_table[id][1]+1		
			return 0

	def login(self,sc,tmp1,id,v0,id_u):
		global lt,lctr,lbw,pbw
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.bind((host,port))
		sock.listen(1)
		conn,addr=sock.accept()
		v1=conn.recv(32)
		did=conn.recv(32)
		t1=conn.recv(32)
		g=conn.recv(32)
		conn.close()
		sock.close()
		l_start=time.clock()	
		t2=bytearray(struct.pack(">i",int(time.time())))
		fresh=1
		for i in range(28):
			t2.append(0)
		t1=bytearray(t1)			
		for i in range(4):
			if t1[i]==t2[i]:
				continue
			elif abs(t1[i]-t2[i])>100:
				fresh=0
			else:
				continue
		if fresh==0:
			print("Aborting because timestamp is not fresh")
			sys.exit(1)
		tmp2=bytearray(decrypt(did))
		did=bytearray(did)
		if reg_table[id][1]<sc.n:
			tmp3=bytearray()
			for i in range(32):
				tmp3.append(v0[i]|id_u[i]|t1[i])
			h1.update(bytes(tmp3))
			tmp4=bytearray(h1.digest())
			tmp5=bytearray()
			for i in range(32):
				tmp5.append((tmp4[i]*g[i])%256)	
			e=bytearray()
			for i in range(32):
				e.append((v1[i]-tmp5[i])%256)	
			u=os.urandom(32)
			n1=os.urandom(32)
			c=bytearray()
			for i in range(32):
				c.append((u[i]*e[i])%256)	
			d=bytearray()
			for i in range(32):
				d.append((u[i]*g[i])%256)
			tmp6=bytearray()
			for i in range(32):
				tmp6.append(id[i]|n1[i])
			nid=encrypt(bytes(tmp6))
			h2.update(bytes(c))
			tmp7=h2.digest()
			v2=bytearray()
			for i in range(32):
				v2.append(tmp7[i]^nid[i])
			tmp8=bytearray()
			for i in range(32):
				tmp8.append(nid[i]|c[i]|t2[i])
			h2.update(tmp8)
			v3=h2.digest()
			v3=bytearray(v3)
			l_end=time.clock()
			lt=lt+(l_end-l_start)
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((host,port))
			sock.send(v2)
			sock.send(v3)
			sock.send(d)
			sock.send(t2)
			lbw=lbw+(32*4)
			pbw=pbw+(32*4)
			sock.close()
		else:
			print("Aborting")
			sys.exit(1)	
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.bind((host,port))
		sock.listen(1)
		conn,addr=sock.accept()
		v4=conn.recv(32)
		sk=conn.recv(32)
		conn.close()
		sock.close()
		l_start=time.clock()
		tmp9=bytearray()
		for i in range(32):
			tmp9.append(v1[i]|c[i])
		h2.update(tmp9)
		tmp10=bytearray(h2.digest())
		l_end=time.clock()
		lt=lt+(l_end-l_start)
		lctr=lctr+1
		return self.authenticate(sk)

	def revoke_sc(self,sc,id_u,id_s):
		global st,sctr,sbw
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.bind((host,port))
		sock.listen(1)
		conn,addr=sock.accept()
		id_u_recvd=conn.recv(1024)
		conn.close()
		sock.close()
		id_u_recvd=bytearray(id_u)
		if id_u_recvd==id_u:
			s_start=time.clock()
			ci=bytearray(os.urandom(32))
			n0=bytearray(os.urandom(32))
			id=bytearray()
			for i in range(32):
				id.append(id_u[i]|id_s[i]|ci[i])
			tmp1=bytearray()
			for i in range(32):
				tmp1.append(id[i]|n0[i])		
			did=encrypt(bytes(tmp1))
			did=bytearray(did)	
			tmp2=bytearray()
			for i in range(32):
				tmp2.append(id[i]|x[i])	
			h1.update(bytes(tmp2))
			v0=bytearray(h1.digest())
			sc.did=did
			sc.v0=v0
			s_end=time.clock()
			st=st+(s_end-s_start)
			sctr=sctr+1
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((host,port))
			sock.send(pickle.dumps(sc))
			sock.close()
			sbw=sbw+56
			id=tuple(id)
			reg_table[id]=[ci,0]
			id=bytearray(id)
		else:
			print("User not registered")
			sys.exit(1)	

if __name__=="__main__":
	server=Server()
	while 1:
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.bind((host,port))
		sock.listen(1)
		conn,addr=sock.accept()
		c=conn.recv(1).decode()
		conn.close()
		sock.close()
		if c=='1':
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.bind((host,port))
			sock.listen(1)
			conn,addr=sock.accept()
			id_u=conn.recv(1024)
			id_u=bytearray(id_u)
			(did,v0,tmp1,id,id_s)=server.register(id_u)
			id=tuple(id)
			sc=SmartCard(did,v0)
			conn.send(pickle.dumps(sc))
			conn.close()
			sock.close()
			rbw=rbw+56
		elif c=='2':	
			ctr=0
			while (ctr<sc.n) and (not server.login(sc,tmp1,id,v0,id_u)):
				ctr=ctr+1
		elif c=='3':	
			ctr=0
			while (ctr<sc.n) and (not server.login(sc,tmp1,id,v0,id_u)):
				ctr=ctr+1		
		elif c=='4':		
			server.revoke_sc(sc,id_u,id_s)	
		else:
			break

	rdelay=rt/rctr
	ldelay=lt/lctr
	pdelay=ldelay
	sdelay=st/sctr			
	print("\nExecution time:\n")
	print("Registration phase: {0}".format(rdelay))
	print("Login phase: {0}".format(ldelay))
	print("Password change phase: {0}".format(pdelay))
	print("Smart card revocation phase: {0}\n".format(sdelay))
	print("Total execution time: {0}\n".format(rdelay+ldelay+pdelay+sdelay))				
	rbytes=rbw/rctr
	lbytes=lbw/rctr
	pbytes=pbw/rctr			
	sbytes=sbw/rctr
	print("Bytes sent:\n")
	print("Registration phase: {0}".format(rbytes))
	print("Login phase: {0}".format(lbytes))
	print("Password change phase: {0}".format(pbytes))
	print("Smart card revocation phase: {0}\n".format(sbytes))
	print("Total no. of bytes sent: {0}\n".format(rbytes+lbytes+pbytes+sbytes))	