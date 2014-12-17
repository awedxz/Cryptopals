from random import randint
from Crypto.Hash import SHA
from binascii import unhexlify

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
#g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
g = 0

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def invmod(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def sign(m, x, k = 0): # m - message; x - priv key
    global p, q, g
    r = 0
    s = 0
    sha = SHA.new()
    sha.update(m)
    Hm = unhexlify(sha.hexdigest())
    
    Hm = int.from_bytes(Hm, byteorder='big')
    
    while s == 0:
        if k == 0:
            k = randint(1, q - 1)
            r = fast_pow(g, k, p) % q
        s = (invmod(k, q) * (Hm + x * r)) % q
        
    return (r, s)

def verify(r, s, m, y): # y - public key
    global p, q, g
    sha = SHA.new()
    sha.update(m)
    Hm = unhexlify(sha.hexdigest())
    Hm = int.from_bytes(Hm, byteorder='big')
    
    # this problem assumes we don't do this
    #if r <= 0 or r >= q:
    #    return False
    #if s <=0 or s >= q:
    #    return False

    w = invmod(s, q)
    uone = (Hm * w) % q
    utwo = (r * w) % q
    v = ((fast_pow(g, uone, p) * fast_pow(y, utwo, p)) % p) % q

    if v == r:
        return True

    return False

def gen_user_key():
    global p, q, g
    x = randint(1, q - 1)
    y = fast_pow(g, x, p)
    return (y, x) # y - public; x - private
    
def fast_pow(x, y, z):
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

def main():
    global q, g, p

    m = b'hi mom'
    k = randint(0, q - 1)
    pub, priv = gen_user_key()
    r, s = sign(m, priv, k)
    assert(verify(r, s, m, pub) == True)
    assert(verify(r, s, b'another', pub) == True) # since g = 0, anything will pass

    g = (p + 1)
    pub, priv = gen_user_key()
    m1 = b'Hello, world'
    m2 = b'Goodbye, world'

    # what is z? 
    z = 2 

    # signing without the private key!!!
    r = (fast_pow(pub, z, p) % q)
    s = (invmod(z, q) * r) % q
    
    assert(verify(r, s, m1, pub))
    assert(verify(r, s, m2, pub))

if __name__ == '__main__':
    main()
