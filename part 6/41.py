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

# could refactor this using better method
def encrypt(msg, e, n):
    enc_blocks = []

    for i in range(int(len(msg) / 15) + 1):
        m = int(hexlify(bytes(msg[i * 15:(i + 1) * 15], 'ascii')), 16)
        assert(m < n)
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
        p = get_prime(128, 64)
        q = get_prime(128, 64)
        n = p * q
        et = (p - 1) * (q - 1) # ϕ / totient aka number of relative primes in n
        e = 3

        # choose some integer e such that 1 < e < ϕ(n) and gcd(e, ϕ(n)) = 1
        # ensure e == 3
        if coprime([e, et]):
            # uses the EEA to find x, y (- Z such that
            # xe + yϕ(n) = 1. Let d be the remainder of the
            # division of x by ϕ(n).
            d = invmod(e, et)
            return (e, d, n)

def main():
    msg = "tester"

    # let N and E be the public key
    E, D, N = gen_keys()

    # capture ciphertext C
    C = encrypt(msg, E, N)

    # Let S be a random number > 1 % N
    S = randint(1 % N, (1 % N) + 0xFFFF)

    # C' = ((S**E mod N) C) mod N
    Cprime = (fast_pow(S, E, N) * C[0]) % N

    #Submit C', which appears totally different from C, to the server,
    # recovering P', which appears totally different from P
    Pprime = decrypt([Cprime], D, N) # 'server' has the private key
    
    hexd = hexlify(Pprime)
    while len(hexd) % 2 is not 0:
        hexd += b'\x00'
    
    # Now:
    #       P'
    # P = -----  mod N
    #       S

    # You don't simply divide mod N; you multiply by the
    # multiplicative inverse mod N.

    Pint = (int(hexd, 16) * invmod(S, N)) % N
    Pinthexd = format(Pint, 'x')

    while len(Pinthexd) % 2 is not 0:
        Pinthexd += '0'

    P = unhexlify(Pinthexd)
    assert(P == bytes(msg, 'ascii'))

if __name__ == '__main__':
    main()
