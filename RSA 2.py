from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

def keys():
    key = RSA.generate(1024)

    private_key = key.export_key()
    file_out = open("privkey", "wb") #wb Создает двоичный файл для записи.
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("pubkey", "wb")
    file_out.write(public_key)
    file_out.close()

def enc():
    data = "Erbolat".encode("utf-8")
    file_out = open("cipher", "wb")

    recipient_key = RSA.import_key(open("pubkey").read())
    session_key = get_random_bytes(16)

    # Зашифровать сеансовый ключ открытым ключом RSA
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Зашифровать данные с помощью сеансового ключа AES
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()

def dec():
    file_in = open("cipher", "rb") #rb Открывает двоичный файл для чтения.

    private_key = RSA.import_key(open("privkey").read())

    enc_session_key, nonce, tag, ciphertext = \
       [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Расшифровать сеансовый ключ с помощью закрытого ключа RSA
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Расшифровать данные с помощью сеансового ключа AES
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))

    