'''
    24. Create the MT19937 Stream Cipher And Break It

    You can create a trivial stream cipher out of any PRNG; use it to
    generate a sequence of 8 bit outputs and call those outputs a
    keystream. XOR each byte of plaintext with each successive byte of
    keystream.

    Write the function that does this for MT19937 using a 16-bit
    seed. Verify that you can encrypt and decrypt properly. This code
    should look similar to your CTR code.

    Use your function to encrypt a known plaintext (say, 14 consecutive
    'A' characters) prefixed by a random number of random characters.

    From the ciphertext, recover the "key" (the 16 bit seed).

    Use the same idea to generate a random "password reset token" using
    MT19937 seeded from the current time.

    Write a function to check if any given password token is actually
    the product of an MT19937 PRNG seeded with the current time.
'''
from random import randint
from math import ceil
from struct import unpack
from time import time

class MersenneTwister(object):
    def __init__(self, seed):
        # Create a length 624 array to store the state of the generator
        self.len = 623
        self.MT = [None] * self.len
        self.index = 0
        self.mask = (2**32) - 1
        self.Zerox8 = 2**31
        self.init_gen(seed)
        
    def init_gen(self, seed):
        self.MT[0] = seed

        # loop over each other element
        for i in range(1, self.len):
            self.MT[i] = (1812433253 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i) & self.mask
                      
    def extract_num(self):
        if (self.index == 0):
            self.generate_numbers()
            
        y = self.MT[self.index]
        
        y ^= y >> 11
        y ^= (y << 7) & 2636928640        
        y ^= (y << 15) & 4022730752
        y ^= y >> 18
        
        self.index = (self.index + 1) % self.len
        return y
            
    def generate_numbers(self):
        for i in range(self.len):
            y = (self.MT[i] & self.Zerox8) + (self.MT[(i+1) % self.len] & (self.Zerox8 - 1))
            self.MT[i] = self.MT[(i + 397) % self.len] ^ (y >> 1)
            
            if y % 2:
                self.MT[i] ^= 2567483615
                       

def mt_crypt(d, k):
    prng = MersenneTwister(k)
    keystream = bytearray()
    enc = b''
    
    for i in range(len(d)):
       num = prng.extract_num()
       keystream += num.to_bytes(4, 'little')
        
    return xor_encrypt(d, keystream)

    
def reverse_lbitshift_xor(y, n, magic):
    if n == 7: 
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
    else:
        y ^= (y << n) & magic
        
    return y
  
  
def reverse_rbitshift_xor(y, n):
    if y == 18:
        y ^= y >> (n)
    else:
        y ^= y >> (n)
        y ^= y >> (n)
        y ^= y >> (n)
    return y
  
  
def inverse_temper(y):
    y = reverse_rbitshift_xor(y, 18)
    y = reverse_lbitshift_xor(y, 15, 4022730752)
    y = reverse_lbitshift_xor(y, 7, 2636928640)
    y = reverse_rbitshift_xor(y, 11)

    return y
    
    
def temper(y):
    y ^= y >> 11
    y ^= (y << 7) & 2636928640        
    y ^= (y << 15) & 4022730752
    y ^= y >> 18
    
    return y
    
    
def xor_encrypt(block, key):
    return bytes([a^b for (a,b) in zip(key, block)])
    
    
def random_chars(num = 10):
    chars = b''
    
    for i in range(randint(1, num)):
        chars += bytes(chr(randint(32, 127)), 'ascii')
    
    return chars


def get_key(ct, pt):
    ks = xor_encrypt(ct, pt)
    seed = 0
    
    rnd_size = len(ks) - 14 # get size of random block
    first_idx = ceil(rnd_size / 4) * 4
    
    ms = ks[first_idx:first_idx + 4] # get four bytes of MT output
    ms = unpack("<L", ms)[0] # convert back to 32 bit int

    # super slow, ugly, and brute force, but the only way I can think
    # to do this right now
    for i in range(0, 65536):
        prng = MersenneTwister(i)
        for j in range(first_idx + 1):
            test = prng.extract_num()
            if test == ms:
                seed = i
                break
        
    return seed
    
    
def test_mt_enc():
    pt = b'AAAAAAAAAAAAAAAA'
    pt1 = b'BBBBBBBBBBBB'
    k = randint(0, 65535) # unsigned short int max size (16 bit)
    
    cipher = mt_crypt(pt, k)
    rpt = mt_crypt(cipher, k)
    
    assert pt == rpt
    
    cipher1 = mt_crypt(pt1, k)
    rpt1 = mt_crypt(cipher1, k)
    
    assert pt1 == rpt1


def crack_key():
    pt = random_chars() + b'AAAAAAAAAAAAAA'
    k = randint(0, 65535)
    ct = mt_crypt(pt, k)
    
    ck = get_key(ct, pt)
    
    assert ck == k
    

def gen_token():
    k = int(time())
    data = random_chars(20) + b'password reset' + random_chars(10)
    return mt_crypt(data, k)
      

def test_token(t, expiry_window = 0):
    current_time = int(time())
    valid = False

    for i in range(current_time, current_time - expiry_window, -1):
        test = mt_crypt(t, i)
        if b'password reset' in test:
            valid = True
    
    return valid
      
      
def main():
    test_mt_enc() # test enc / decrypt of mt keystream
    crack_key() # find key from ct output - slowwwww
    
    token = gen_token()
    print(test_token(token, 15))
    print(test_token(token, 1))
    print(test_token(token, 0))
        
if __name__ == '__main__':
    main()