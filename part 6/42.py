from random import randint, getrandbits, randrange
from binascii import hexlify, unhexlify
from itertools import combinations
from Crypto.Hash import SHA

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def gcd(a, b):
    a = abs(a)
    b = abs(b)
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a

def invmod(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def get_prime(bits, k):
    prime = getrandbits(bits)
    while not is_prime(prime, k):
        prime = getrandbits(bits)
    return prime

small_primes = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
    61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
    131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
    271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
    433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
    601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673,
    677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761,
    769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857,
    859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
    953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031,
    1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
    1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163
]

def coprime(l):
    for i, j in combinations(l, 2):
        if gcd(i, j) != 1:
            return False
    return True

def is_prime(n, k): 
    if n < 2: return False
    for p in small_primes:
        if n < p * p: return True
        if n % p == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = randrange(2, n - 1)
        x = fast_pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = fast_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def fast_pow(x, y, z):
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

def change_base(m, n):
    c = []
    running_total = 0
    i = 0

    # could be cleaned up a little
    while m - running_total != 0:
        mvals = m
        
        for x in range(i):
            mvals -= c[x] * n ** x

        r = (mvals // (n ** i)) % n
        c.append(r)
        running_total += r * n ** i
        i += 1

    return c

def sign(msg, d, n):
    m = 0
    ret = []

    m = int.from_bytes(msg, byteorder='big')

    if m > n:
        m = change_base(m, n)
    else:
        m = [m]

    for part in m:
        c = fast_pow(part, d, n)
        ret.append(c)

    return ret
    
def de_sign(msg, e, n, s = 128): #wow these names are terrible
    blocks = []
    m = 0
    i = 0

    for i, block in enumerate(msg):
        dec = fast_pow(block, e, n)
        blocks.append(dec.to_bytes(s, byteorder='big'))

    return b''.join(blocks)

def iroot(k, n): #newton's method
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

def gen_keys(size = 256):
    while True:
        p = get_prime(size, 64)
        q = get_prime(size, 64)
        n = p * q
        
        if n.bit_length() != size * 2:
            continue
        
        et = (p - 1) * (q - 1)
        e = 3 #normal implementations would alter this, not everything else

        if coprime([e, et]): # ensure bit legnth is correct
            d = invmod(e, et)
            return (e, d, n)

def check_sig(enc, e, n):
    last_idx = 3
    check = de_sign(enc[:-1], e, n) # decrypt
    msg = enc[-1:][0]
    sha = SHA.new()
    sha.update(msg)
    hsh = unhexlify(sha.hexdigest()) # hash msg

    # the bad padding checker
    if check[0:3] == b'\x00\x01\xff': 
        for byte in check[3:]:
            if byte == 255:
                last_idx += 1
            else:
                 break

        if check[last_idx] != 0:
            return False

    da_hash = check[last_idx + 16:last_idx + 16 + 20] # jump over ASN.1 since not using it
 
    if (da_hash == hsh):
        return True

    return False

def forge_sig(hsh, e, mod):
    mid = b'\x00' +  b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x20' + hsh # 36 bytes
    payload = b'\x00\x01' + (b'\xff' * 2) + mid # 46 bytes total
    tail = b'\x00' * (128 - len(payload))  # 82 for garbage

    attack = payload + tail
    place = 1
    taillen = len(tail)

    while True:
        D = int.from_bytes(attack, byteorder='big')
        sig = iroot(3, D) + 1
        test = sig ** 3

        x = test.to_bytes(128, byteorder='big')
 
        if x[:40] == attack[:40]:
             break

        # try very simple brute force first? - not needed
        if tail[place] == 255:
            tail = tail[:taillen - place] + b'\x00' + tail[taillen - place + 1:]
            place += 1
            print('---')
            print(payload)
            print()
            print(x[:46])
            print('---')

        tail = tail[:place] + bytes([tail[place] + 1]) + tail[place + 1:]
        attack = payload + tail
    
    return [sig]

def main():
    e, d, n = gen_keys(512) # generates a keysize of size * 2
    sha = SHA.new()
    msg = b'hi mom'
    sha.update(msg)
    hsh = sha.hexdigest()
    hsh = unhexlify(hsh)
  
    k = 1024 // 8 # length in bytes
    ASN1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x20'
    barbarDbarbar = len(hsh) + len(ASN1) # length in bytes

    valid_sig = b'\x00' + b'\x01' + (b'\xFF' * (k - 3 - barbarDbarbar)) + b'\x00' + ASN1 + hsh
    enc = sign(valid_sig, d, n)
    
    data = enc.append(msg) # data + signature for data

    dec = de_sign(enc[:-1], e, n)

    assert(valid_sig == dec) # make we can sign / design sigs correctly
    assert(check_sig(enc, e, n)) # make sure we can check valid hashes
    
    forged = forge_sig(hsh, e, n)
    forged.append(msg)

    assert(check_sig(forged, e, n)) # check forged works

if __name__ == '__main__':
    main()
