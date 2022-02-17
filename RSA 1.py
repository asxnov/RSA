from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Cipher import PKCS1_OAEP

def script(msg):
	priv = RSA.generate(1024, Random.new().read)
	public = priv.publickey()
	print(priv.exportKey().decode())
	print()
	print(public.exportKey().decode())

	print()

	encrypted = PKCS1_OAEP.new(public).encrypt(msg)
	print(encrypted)
	print()
	decrypted = PKCS1_OAEP.new(priv).decrypt(encrypted)
	print(decrypted.decode())

script(b'Sib 18 3')