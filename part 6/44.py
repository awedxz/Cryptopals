from random import randint
from Crypto.Hash import SHA
from binascii import unhexlify

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

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
        while r == 0:
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
    
    if r <= 0 or r >= q:
        return False
    if s <=0 or s >= q:
        return False

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

def findx(s, k, r, m):
    global q
    sha = SHA.new()
    sha.update(m)
    Hm = unhexlify(sha.hexdigest())
    Hm = int.from_bytes(Hm, byteorder='big')
    return (invmod(r, q) * (s * k - Hm)) % q

def main():
    global q

    y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
    
    # messages signed with the same k have the same r value
    with open('44.txt', 'rU') as f:
        lines = f.readlines()
    
    rmap = {}
    mmap = {}
    smap = {}
    msgmap = {}
    i = 0

    # create maps of values
    for val in lines:
        if val[0] == 'r':
            rmap[i] = val[3:-1]
        elif val[0] == 'm' and val[1] == 's':
            msgmap[i] = val[5:-1] # newline plus space
        elif val[0] == 'm':
            mmap[i] = val[3:-1]
            i += 1
        else:
            smap[i] = val[3:-1]

    dupidxes = []
    j = 0

    # find duplicate item(s)
    for key, val in rmap.items():
        for key2, val2 in rmap.items():
            if key == key2:
                continue
            if val == val2:
                dupidxes.append([key, key2])
        j += 1
        if j > (i / 2): # only need to run through half of the map
            break

    m1 = unhexlify(mmap[dupidxes[0][0]])
    m1 = int.from_bytes(m1, byteorder='big')
    m2 = unhexlify(mmap[dupidxes[0][1]])
    m2 = int.from_bytes(m2, byteorder='big')

    k = (invmod(int(smap[dupidxes[0][0]]) - int(smap[dupidxes[0][1]]), q) * (m1 - m2)) % q
    x = findx(int(smap[dupidxes[0][0]]), k, int(rmap[dupidxes[0][0]]), bytes(msgmap[dupidxes[0][0]], 'ascii'))

    # then find the private key based on that
    realfinger = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
    priv = bytes(hex(x)[2:], 'ascii')
    sha = SHA.new()
    sha.update(priv)
    fingerprime = sha.hexdigest()    
    assert(fingerprime == realfinger)

if __name__ == '__main__':
    main()
