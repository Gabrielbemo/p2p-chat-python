import rsa

with open("public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

mensagem = "teste 123"

mensagem_criptografada = rsa.encrypt(mensagem.encode(), public_key)

print(mensagem_criptografada)

mensagem_descriptografada = rsa.decrypt(mensagem_criptografada, private_key)

print(mensagem_descriptografada)
print(mensagem_descriptografada.decode())

mensagem_assinada = "abacaxi"

#assinatura = rsa.sign(mensagem_assinada.encode(), private_key, "SHA-256")

#with open("assinatura", "wb") as f:
#    f.write(assinatura)

with open("assinatura", "rb") as f:
    assinatura = f.read()

print(rsa.verify(mensagem_assinada.encode(), assinatura, public_key))



#public_key, private_key = rsa.newkeys(1024)

#with open("public.pem", "wb") as f:
#    f.write(public_key.save_pkcs1("PEM"))

#with open("private.pem", "wb") as f:
#        f.write(private_key.save_pkcs1("PEM"))
