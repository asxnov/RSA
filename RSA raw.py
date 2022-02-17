def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def gcd(a, b):  
    while b != 0:
        a, b = b, a % b
    return a

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generate_keyPairs():
    p = 3
    q = 11
    
    n = p*q
    print("n = ",n)
    phi = (p-1) * (q-1) 
    print("phi = ",phi)
       
    e = 257
    g = gcd(e,phi)
    while g != 1:
        
        g = gcd(e, phi)
        
    print("e =",e)
    d = egcd(e, phi)[1]

    d = d % phi  
    if(d < 0):
        d += phi
        
    return ((e,n),(d,n))
        
def encrypt(text,public_key):
    key,n = public_key
    ctext = [pow(ord(char),key,n) for char in text]
    return ctext

def decrypt(ctext,private_key):
    try:
        key,n = private_key
        text = [chr(pow(char,key,n)) for char in ctext]
        return "".join(text)
    except TypeError as e:
        print(e)

if __name__ == '__main__':
    public_key,private_key = generate_keyPairs() 
    print(public_key)
    print(private_key)

    
    ctext = encrypt('Asanov Erbolat',public_key)
    print("encrypted =", ctext)
    
    plaintext = decrypt(ctext, private_key)
    print("decrypted =", plaintext)
