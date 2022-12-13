#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
import rsa
import json
from cryptography.fernet import Fernet

#   ---- Gerando a chave publica, privada e salvando em um arquivo ----
public_key, private_key = rsa.newkeys(1024)

#salvando chaves como pem e criando variaveis para a logica
pem_public_key = public_key.save_pkcs1("PEM");
pem_private_key = private_key.save_pkcs1("PEM");
pem_public_key_other_chat = ""
symmetric_key = ""
fernetObject = None

template = { "type":"", "data":"", "signature":""}

send = 1
symetric = 1
class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def signMessage(self, msg):
        return rsa.sign(msg, private_key, 'MD5')

    def run(self):
        global send
        global symetric
        global fernetObject
        lis=[]
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            #verifica o tipo de mensagem, seta chaves simetricas e valida as assinaturas
            for item in read:
                try:
                    s = item.recv(1024)
                    jj = s.decode();
                    jsonConverted = json.loads(jj)

                    if jsonConverted["type"] == "msg" and send == 2:
                        chunk = s
                        chavepublicasdooutro = rsa.PublicKey.load_pkcs1(pem_public_key_other_chat)
                        msgDencrypted = fernetObject.decrypt(jsonConverted["data"])
                        if rsa.verify(msgDencrypted, bytes.fromhex(jsonConverted["signature"]), chavepublicasdooutro) == "MD5":
                            print(msgDencrypted.decode())
                        else:
                            print("assinatura não valida")

                    if jsonConverted["type"] == "public" and send == 1:
                        send = 2
                        template["type"] = "second_public"
                        template["data"] = pem_public_key.decode()
                        print("Configurou a chave publica primeiro")
                        pem_public_key_other_chat = jsonConverted["data"]
                        self.receive.send(json.dumps(template).encode())

                    if jsonConverted["type"] == "second_public" and send == 1:
                        send = 2
                        print("Configurou a chave publica segundo")
                        template["type"] = "third_public"
                        template["data"] = pem_public_key.decode()
                        pem_public_key_other_chat = jsonConverted["data"]
                        self.receive.send(json.dumps(template).encode())

                    if jsonConverted["type"] == "third_public" and send == 2:
                        symetric = 2
                        print("Configurou a chave symetrica primeiro")
                        symmetric_key = Fernet.generate_key()
                        fernetObject = Fernet(symmetric_key)

                        signature = self.signMessage(symmetric_key)

                        chavepublicasdooutro = rsa.PublicKey.load_pkcs1(pem_public_key_other_chat)
                        symmetric_key_encrypted = rsa.encrypt(symmetric_key, chavepublicasdooutro)
                        template["type"] = "symmetric"

                        template["data"] = symmetric_key_encrypted.hex()
                        template["signature"] = signature.hex()
                        self.receive.send(json.dumps(template).encode())

                    if jsonConverted["type"] == "symmetric":
                        print("Configurou a chave symetrica segundo")

                        symmetric_key_encrypted = bytes.fromhex(jsonConverted["data"])
                        symmetric_key = rsa.decrypt(symmetric_key_encrypted, private_key)
                        chavepublicasdooutro = rsa.PublicKey.load_pkcs1(pem_public_key_other_chat)
                        if rsa.verify(symmetric_key, bytes.fromhex(jsonConverted["signature"]), chavepublicasdooutro) == "MD5":
                            fernetObject = Fernet(symmetric_key)

                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def signMessage(self, msg):
        return rsa.sign(msg, private_key, 'MD5')

    def client(self, host, port, msg):
        sent = self.sock.send(rsa.encrypt(msg.encode(), public_key))
        # print "Sent\n"

    def clientSimplified(self, msg):
        sent = self.sock.send(msg)
        # print "Sent\n"

    def run(self):
        global fernetObject
        global send
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            host = input("Enter the hostname\n>>")
            port = int(input("Enter the port\n>>"))
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service\n")
        srv.start()
        time.sleep(5)
        print("Service started\n")

        #loop para enviar a primeira chave publica
        while send == 1:
            print("Enviando Chave Publica --->\n")
            time.sleep(3)

            template["type"] = "public"
            template["data"] = pem_public_key.decode()
            self.clientSimplified(json.dumps(template).encode())

        print("Chat configurado - pronto para uso\n")

        #loop para enviar mensagem
        while 1:
            # print "Waiting for message\n"
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            # print "Sending\n"
            template["type"] = "msg"
            msgEncrypted = fernetObject.encrypt(msg.encode())
            template["data"] = msgEncrypted.decode()
            signature = self.signMessage(msg.encode())
            template["signature"] = signature.hex()
            #templateJSON = json.dumps(template)
            self.clientSimplified(json.dumps(template).encode())
        return (1)


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
