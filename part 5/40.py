from random import randint, getrandbits, randrange
from binascii import hexlify, unhexlify
from itertools import combinations

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

def is_prime(n, k): # Miller-Rabin
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
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
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

def encrypt(msg, e, n):
    enc_blocks = []

    for i in range(int(len(msg) / 15) + 1):
        m = int(hexlify(bytes(msg[i * 15:(i + 1) * 15], 'ascii')), 16)
        c = fast_pow(m, e, n)
        enc_blocks.append(c)

    return enc_blocks

def decrypt(cipher, d, n):
    blocks = []

    for block in cipher:
        dec = fast_pow(block, d, n)
        blocks.append(unhexlify(format(dec, 'x')))

    return b''.join(blocks)

def gen_keys():
    while True:
        p = get_prime(64, 64)
        q = get_prime(64, 64)
        n = p * q
        et = (p - 1) * (q - 1) # totient
        e = 3

        # ensure e == 3
        if coprime([e, et]):
            d = invmod(e, et)
            return (e, d, n)

def main():
    msg = "tester"
    e0, d0, n0 = gen_keys()
    e1, d1, n1 = gen_keys()
    e2, d2, n2 = gen_keys()

    c0 = encrypt(msg, e0, n0)
    c1 = encrypt(msg, e1, n1)
    c2 = encrypt(msg, e2, n2)

    avals = [c0, c1, c2]
    nvals = [n0, n1, n2]

    N = n0 * n1 * n2
    ms0 = n1 * n2
    ms1 = n0 * n2
    ms2 = n0 * n1

    result = (c0[0] * ms0 * invmod(ms0, n0))
    result += (c1[0] * ms1 * invmod(ms1, n1))
    result += (c2[0] * ms2 * invmod(ms2, n2))

    dec = round((result % N) ** (1/3)) # works for size(msg) <= 6... revist later

    assert(unhexlify(format(dec, 'x')) == bytes(msg, 'ascii'))

if __name__ == '__main__':
    main()
