import os
import socket
import pickle
import struct
import sys
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import face_recognition as frec
import cv2

host=socket.gethostbyname(socket.gethostname())
port=5000
server='localhost'
h1=SHA256.new()
h2=SHA256.new()
h2_dash=SHA256.new()

def get_image(camera):
	retval, im = camera.read()
	return im

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
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.connect((server,port))
		sock.send(self.id_u)
		sc=SmartCard()
		data=sock.recv(1024)
		sc=pickle.loads(data)
		print("Enter an 8-character password:")
		pw=input()
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
		camera_port = 0 
		ramp_frames = 10
		camera = cv2.VideoCapture(camera_port)
		for i in range(ramp_frames):
			temp = get_image(camera)
		print("Stay still while taking image...")
		camera_capture = get_image(camera)
		file = "./known_image.png"
		cv2.imwrite(file, camera_capture)
		del(camera)
		return sc,v0,pw

	def authenticate(self,sc,sk,pd):
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.connect((server,port))
		print("Enter the password:")
		pw=input()
		pw=bytearray(pw.encode())	
		camera_port = 0 
		ramp_frames = 10
		camera = cv2.VideoCapture(camera_port)
		for i in range(ramp_frames):
			temp = get_image(camera)
		print("Stay still while taking image...")
		camera_capture = get_image(camera)
		file = "./unknown_image.png"
		cv2.imwrite(file, camera_capture)
		del(camera)
		known_image=frec.load_image_file("known_image.png")
		unknown_image=frec.load_image_file("unknown_image.png")
		known_encoding=frec.face_encodings(known_image)[0]
		unknown_encoding=frec.face_encodings(unknown_image)[0]
		results=frec.compare_faces([known_encoding],unknown_encoding)
		for i in range(24):
			pw.append(0)
		if pw==pd and results[0]==True:
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
		if sc.ctr_sc<sc.n:
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
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(v1)
			sock.send(sc.did)
			sock.send(t1)
			sock.send(g)
			sock.close()
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
			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((server,port))
			sock.send(v4)
			sock.send(sk)
			sock.close()
			self.authenticate(sc,sk,pd)

	def change_password(self,sc,v0,pd):
		self.login(sc,v0,pd)
		print("Enter the new password:")
		pw_new=input()
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
		return pw_new

	def revoke_sc(self,sc):
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.connect((server,port))
		sock.send(self.id_u)
		sock.close()
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sock.bind((server,port))
		sock.listen(1)
		conn,addr=sock.accept()
		data=conn.recv(1024)
		sc=pickle.loads(data)
		conn.close()
		sock.close()
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
