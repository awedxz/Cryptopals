from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto.Util import Counter
from math import floor
from base64 import b64decode

class CTRCounter(object):
    def __init__(self, bits=64, init=0, nonce=b'', little_endian = True):
        self.bits = bits
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

    
def test():
    # NIST Example Vector #1
    # Make sure my counter / encryption / decryption matches 
    # pycryptos (mostly)
    
    pt = unhexlify(b'6bc1bee22e409f96e93d7e117393172a')
    k = unhexlify(b'2b7e151628aed2a6abf7158809cf4f3c')
    exp = b'874d6191b620e3261bef6864990db6ce'
    exp2 = b'6bc1bee22e409f96e93d7e117393172a'
    
    ctrn = Counter.new(128, initial_value = int(b'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 16))
    ctr = CTRCounter(bits = 128, init = int(b'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 16), little_endian = False)

    cipher = AES.new(k, AES.MODE_CTR, counter=ctrn)
    
    a = hexlify(cipher.encrypt(pt))
    b = hexlify(ctr_encrypt(pt, k, ctr))
    
    assert a == b == exp
    
    ctrn = Counter.new(128, initial_value = int(b'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 16))
    ctr2 = CTRCounter(bits = 128, init = int(b'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 16), little_endian = False)
    
    cipher = AES.new(k, AES.MODE_CTR, counter=ctrn)
     
    c = hexlify(cipher.decrypt(unhexlify(a)))
    d = hexlify(ctr_decrypt(unhexlify(b), k, ctr2))
    
    assert c == d == exp2

def main():
   
    nonce = b'\x00' * 8
    ct = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    key = b'YELLOW SUBMARINE'
    
    ct = b64decode(ct)
    ctr = CTRCounter(bits = 64, init = 0, nonce=nonce, little_endian = True)
    dec = ctr_decrypt(ct, key, ctr)
    print(dec) 

    test()    
    

if __name__ == '__main__':
    main()
