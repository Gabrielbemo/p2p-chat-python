#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
import rsa

#   ---- Gerando a chave publica, privada e salvando em um arquivo ----
# public_key, private_key = rsa.newkeys(1024)
# with open("public.pem", "wb") as f:
#    f.write(public_key.save_pkcs1("PEM"))
# with open("private.pem", "wb") as f:
#        f.write(private_key.save_pkcs1("PEM"))

#   ---- Lendo as chaves ----
with open("public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

class Server(threading.Thread):
    def initialise(self,receive):
        self.receive=receive
    def run(self):
        lis=[]
        lis.append(self.receive)
        while 1:
            read,write,err=select.select(lis,[],[])
            for item in read:
                try:
                    s=item.recv(1024)
                    if s!='':
                        chunk=s                
                        print(str('')+':'+rsa.decrypt(chunk, private_key).decode())
                except:
                    traceback.print_exc(file=sys.stdout)
                    break

class Client(threading.Thread):    
    def connect(self,host,port):
        self.sock.connect((host,port))
    def client(self,host,port,msg):               
        sent=self.sock.send(rsa.encrypt(msg.encode(), public_key))
        #print "Sent\n"
    def run(self):
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)



        try:
            host=input("Enter the hostname\n>>")
            port=int(input("Enter the port\n>>"))
        except EOFError:
            print("Error")
            return 1
        
        print("Connecting\n")
        s=''
        self.connect(host,port)
        print("Connected\n")
        receive=self.sock
        time.sleep(1)
        srv=Server()
        srv.initialise(receive)
        srv.daemon=True
        print("Starting service")
        srv.start()
        while 1:            
            #print "Waiting for message\n"
            msg=input('>>')
            if msg=='exit':
                break
            if msg=='':
                continue
            #print "Sending\n"
            self.client(host,port,msg)
        return(1)
if __name__=='__main__':
    print("Starting client")
    cli=Client()    
    cli.start()
