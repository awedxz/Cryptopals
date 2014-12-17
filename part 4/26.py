'''
CTR bitflipping
There are people in the world that believe that CTR resists bit flipping
attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode
instead of CBC mode. Inject an "admin=true" token.
'''

from Crypto.Cipher import AES
from math import floor
from random import randint
from struct import pack

k = b''

class CTRCounter(object):
    def __init__(self, bits=64, init=0, nonce=b'', little_endian = True):
        self.bits = bits
        self.init = init
        self.count = init - 1
        self.nonce = nonce
        self.little_endian = little_endian

    def __call__(self):
        self.count += 1
        num_bytes = int((self.count.bit_length()) / 8)
        num_bytes = 1 if (num_bytes < 1) else num_bytes
        other_bytes = b'\x00' * floor(((self.bits / 8) - num_bytes))
        if self.little_endian:
            return self.nonce + (self.count).to_bytes(num_bytes, byteorder='little') + other_bytes
        else:
            return self.nonce + other_bytes + (self.count).to_bytes(num_bytes, byteorder='big')

    def reset(self):
        self.count = self.init - 1

def gen_key(length=16):
    key = bytes()
    for i in range(length):
        key += pack('B', randint(0,255))

    return key

def ctr_encrypt(data, key, ctr, nonce = None):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    blocks = get_blocks(data)

    encry = bytes()

    for block in blocks:
        number = ctr()
        enc = cr.encrypt(number)
        ct = xor_encrypt(enc, block)
        encry += ct

    return encry

def ctr_decrypt(data, key, ctr, nonce = None):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    blocks = get_blocks(data)

    decry = bytes()

    for block in blocks:
        number = ctr()
        enc = cr.encrypt(number)
        pt = xor_encrypt(enc, block)
        decry += pt

    return decry


def get_blocks(data, size=16):
    num_blocks = len(data)//size

    blocks = []
    for i in range(0, num_blocks):
        st = i*size
        blocks.append(data[st:st+size])

    return blocks

# xors bytes against a key
def xor_encrypt(block, key):
    return bytes([a^b for (a,b) in zip(key, block)])

def encrypt_txt(txt):
    global k
    
    iv = b'\x00' * 16
    nonce = b'\x00' * 8
    txt = "comment1=cooking%20MCs;userdata=" + txt + ";comment2=%20like%20a%20pound%20of%20bacon"
    escaped = txt.replace(';', '";"').replace('=', '"="')

    ctr = CTRCounter(bits = 64, init = 0, nonce=nonce, little_endian = True)
    enc = ctr_encrypt(bytes(escaped,'ascii'), k, ctr)

    return enc

def check_admin(data):
    global k
    
    iv = b'\x00' * 16
    nonce = b'\x00' * 8
    ctr = CTRCounter(bits = 64, init = 0, nonce=nonce, little_endian = True)

    txt = ctr_decrypt(data, k, ctr).decode('ascii', 'ignore')
    print(txt)
    admin = "admin=true"

    if admin in txt:
        return True

    return False

def main():
    global k
    k = gen_key()
    iv = b'\x00' * 16
    nonce = b'\x00' * 8

    enc = bytearray(encrypt_txt(";admin true;"))

    first_block = enc[:32]
    second_block = enc[32:48]
    the_rest = enc[48:]

    # from ' ' to =
    second_block[14] = second_block[14] ^ ord(" ") ^ ord("=")
    new_enc = bytes(first_block + second_block + the_rest)

    print(check_admin(new_enc))    

if __name__ == '__main__':
    main()
