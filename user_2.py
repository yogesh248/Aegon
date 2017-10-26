import os
import socket
import pickle
import struct
import sys
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

host=socket.gethostbyname(socket.gethostname())
port=5000
server='localhost'
h1=SHA256.new()
h2=SHA256.new()
h2_dash=SHA256.new()
rt,rctr,lt,lctr,pt,pctr,st,sctr=0,0,0,0,0,0,0,0
rbw,lbw,pbw,sbw=0,0,0,0

class SmartCard:
	def __init__(self,did=None,v0=None,ctr_sc=0,n=3):
		self.did=did
		self.v0=v0
		self.ctr_sc=ctr_sc
		self.n=n
	def increment_counter(self):
		self.ctr_sc=self.ctr_sc+1	
	
class User:
	def __init__(self):
		self.id_u=bytearray(os.urandom(32))

	def register(self):
		global rt,rbw,rctr
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.connect((server,port))
		sock.send(self.id_u)
		rbw=rbw+32
		sc=SmartCard()
		data=sock.recv(1024)
		sc=pickle.loads(data)
		print("Enter an 8-character password:")
		pw=input()
		r_start=time.clock()
		pw=bytearray(pw.encode())
		for i in range(24):
			pw.append(0)
		h1.update(bytes(pw))
		tmp1=bytearray(h1.digest())
		v0=sc.v0
		v=bytearray()
		for i in range(32):
			v.append(sc.v0[i]^tmp1[i])
		sc.v0=v
		sc.ctr_sc=0
		sc.n=3
		sock.close()
		r_end=time.clock()
		rt=rt+(r_end-r_start)
		rctr=rctr+1
		return sc,v0,pw

	def authenticate(self,sc,sk,pd):
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.connect((server,port))
		print("Enter the password:")
		pw=input()
		pw=bytearray(pw.encode())	
		for i in range(24):
			pw.append(0)
		if pw==pd:
			flg='1'
			sock.send(flg.encode())
			sock.close()
			print("Login is successful")
			print("The session key is {0}".format(sk))
			print("\n")
		else:
			flg='0'
			sock.send(flg.encode())
			sock.close()
			sc.increment_counter()
			if sc.ctr_sc==sc.n:
				print("Aborting")
				sys.exit(1)
			else:
				print("Login unsuccessful")
				print("{0} attempts remaining".format(sc.n-sc.ctr_sc))
				print("\n")				

	def login(self,sc,v0,pd):
		global lt,lctr,lbw,pbw
		if sc.ctr_sc<sc.n:
			l_start=time.clock()
			r=bytearray(os.urandom(32))
			g=bytearray(os.urandom(32))
			e=bytearray()
			for i in range(32):
				e.append((r[i]*g[i])%256)	
			tmp1=bytearray()
			t1=bytearray(struct.pack(">i",int(time.time())))
			for i in range(28):
				t1.append(0)
			for i in range(32):
				tmp1.append(v0[i]|self.id_u[i]|t1[i])
			h1.update(bytes(tmp1))
			tmp2=bytearray(h1.digest())
			tmp3=bytearray()
			for i in range(32):
				tmp3.append((tmp2[i]*g[i])%256)
			v1=bytearray()
			for i in range(32):
				v1.append((tmp3[i]+e[i])%256)
			l_end=time.clock()
			lt=lt+(l_end-l_start)	
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(v1)
			sock.send(sc.did)
			sock.send(t1)
			sock.send(g)
			sock.close()
			lbw=lbw+(32*4)
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.bind((server,port))
			sock.listen(1)
			conn,addr=sock.accept()
			v2=conn.recv(32)
			v3=conn.recv(32)
			d=conn.recv(32)
			t2=conn.recv(32)
			conn.close()
			sock.close()
			l_start=time.clock()
			v2=bytearray(v2)
			v3=bytearray(v3)
			d=bytearray(d)
			t2=bytearray(t2)
			t1=bytearray(struct.pack(">i",int(time.time())))
			fresh=1
			for i in range(28):
					t1.append(0)		
			for i in range(4):
				if t1[i]==t2[i]:
					continue
				elif abs(t1[i]-t2[i])>100:
					fresh=0
				else:
					continue
			if fresh==0:
				print("Aborting")
				sys.exit(1)
			c=bytearray()	
			for i in range(32):
				c.append((r[i]*d[i])%256)	
			h2.update(bytes(c))
			tmp4=bytearray(h2.digest())
			nid=bytearray()
			for i in range(32):
				nid.append(v2[i]^tmp4[i])
			tmp5=bytearray()
			for i in range(32):
				tmp5.append(nid[i]|c[i]|t2[i])	
			tmp6=bytearray()
			for i in range(32):
				tmp6.append(v1[i]|c[i])
			h2.update(tmp6)
			v4=bytearray(h2.digest())
			sc.did=nid
			tmp7=bytearray()
			for i in range(32):
				tmp7.append(c[i]|d[i]|e[i])
			h2.update(tmp7)
			sk=h2.digest()
			l_end=time.clock()
			lt=lt+(l_end-l_start)
			lctr=lctr+1			
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(v4)
			sock.send(sk)
			sock.close()
			lbw=lbw+(32*2)
			self.authenticate(sc,sk,pd)

	def change_password(self,sc,v0,pd):
		global pt,pctr
		print("Enter the new password:")
		pw_new=input()
		p_start=time.clock()
		pw_new=bytearray(pw_new.encode())
		for i in range(24):
			pw_new.append(0)
		h1.update(pw_new)
		tmp1=bytearray(h1.digest())
		h1.update(pd)
		tmp2=bytearray(h1.digest())
		tmp3=bytearray()
		for i in range(32):
			tmp3.append(tmp1[i]^tmp2[i])
		v=sc.v0	
		tmp4=bytearray()
		for i in range(32):
			tmp4.append(tmp3[i]^v[i])
		sc.v0=tmp4		
		print("Password successfully changed")
		p_end=time.clock()
		pt=pt+(p_end-p_start)
		pctr=pctr+1
		return pw_new

	def revoke_sc(self,sc):
		global st,sbw,sctr
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.connect((server,port))
		sock.send(self.id_u)
		sock.close()
		sbw=sbw+32
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.bind((server,port))
		sock.listen(1)
		conn,addr=sock.accept()
		data=conn.recv(1024)
		sc=pickle.loads(data)
		conn.close()
		sock.close()
		sctr=sctr+1
		return sc

if __name__=="__main__":
	user=User()
	sc=SmartCard()
	pw=bytearray()
	while 1:
		print("1.Register")
		print("2.Login")
		print("3.Change password")
		print("4.Revoke smart card")
		print("5.Exit")
		print("\n")
		print("Enter your choice:")
		ch=int(input())
		if ch==1:
			c='1'
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(c.encode())
			sock.close()
			sc,v0,pw=user.register()
			print("User has been registered"+"\n")
		elif ch==2:
			c='2'
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(c.encode())
			sock.close()
			user.login(sc,v0,pw)
		elif ch==3:
			c='3'
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(c.encode())
			sock.close()
			pw_new=user.change_password(sc,v0,pw)
			pw=pw_new	
		elif ch==4:
			c='4'
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(c.encode())
			sock.close()
			sc=user.revoke_sc(sc)
			print("Smart card revoked.")
		else:
			c='5'
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(c.encode())
			sock.close()
			break
	rdelay=(rt/rctr)*2
	ldelay=(lt/lctr)*2
	pdelay=(pt/pctr)*2
	sdelay=(st/sctr)*2	
	print("\nExecution time:\n")
	print("Registration phase: {0}".format(rdelay))
	print("Login phase: {0}".format(ldelay))
	print("Password change phase: {0}".format(pdelay))
	print("Smart card revocation phase: {0}\n".format(sdelay))
	print("Total execution time: {0} ms\n".format((rdelay+ldelay+pdelay+sdelay)*1000*2))
	rbytes=rbw/rctr
	lbytes=lbw/rctr
	pbytes=pbw/rctr			
	sbytes=sbw/rctr
	print("Bits sent:\n")
	print("Registration phase: {0}".format(rbytes))
	print("Login phase: {0}".format(lbytes))
	print("Password change phase: {0}".format(pbytes))
	print("Smart card revocation phase: {0}\n".format(sbytes))
	print("Total no. of bits sent: {0}\n".format((rbytes+lbytes+pbytes+sbytes)*2))		
			