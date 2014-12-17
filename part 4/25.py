from binascii import hexlify, unhexlify, a2b_base64
from Crypto.Cipher import AES
from Crypto.Util import Counter
from math import floor
from base64 import b64decode
from random import randint
from struct import pack

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

# cbc decrypt with a 16 byte iv and key
def cbc_decrypt(data, key, iv):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    blocks = get_blocks(data)

    decry = bytes()

    prev_block = iv
    for block in blocks:
        decry += xor_encrypt(cr.decrypt(block), prev_block)
        prev_block = block

    return decry

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

'''Now, write the code that allows you to "seek" into the ciphertext, decrypt,
and re-encrypt with different plaintext. Expose this as a function, like,
"edit(ciphertext, key, offet, newtext)".'''
def edit(ct, key, offset, newtext):
    num_blocks = (len(newtext) // 16) + 1
    start_idx = (offset // 16)
    nonce = b'\x00' * 8

    ctr = CTRCounter(bits = 64, init = start_idx, nonce=nonce, little_endian = True)

    pt = ctr_decrypt(ct[start_idx * 16:(start_idx + num_blocks) * 16], key, ctr)
    pt_start_idx = ((start_idx) * 16) - offset

    pt = pt[:pt_start_idx] + newtext + pt[pt_start_idx + len(newtext):]

    ctr.reset()
    new_ct = ctr_encrypt(pt, key, ctr)

    return ct[:start_idx * 16] + new_ct + ct[(start_idx + num_blocks) * 16:]

def main():
    iv = b'\x00' * 16
    oldkey = b'YELLOW SUBMARINE'
    key = gen_key()
    nonce = b'\x00' * 8

    ctr = CTRCounter(bits = 64, init = 0, nonce=nonce, little_endian = True)

    with open('25.txt', 'rU') as f:
        lines = f.readlines()

    data = ''.join([l.strip() for l in lines])
    data = bytes(a2b_base64(data.encode('ascii')))

    pt = cbc_decrypt(data, oldkey, iv)
    ct = ctr_encrypt(pt, key, ctr)

    '''Imagine the "edit" function was exposed to attackers by means of an API call
    that didn't reveal the key or the original plaintext; the attacker has the
    ciphertext and controls the offset and "new text".

    Recover the original plaintext.'''
    new_ct = edit(ct, key, 0, b'A' * len(ct))
    keyz = xor_encrypt(b'A' * len(ct), new_ct)
    gotcha_pt = xor_encrypt(keyz, ct)

    print(gotcha_pt == pt)

if __name__ == '__main__':
    main()
