import binascii
import struct
from Crypto.Cipher import AES
from random import randint
from collections import Counter

def gen_AES_key(length=16):
    key = bytes()
    for i in range(length):
        key += struct.pack('B', randint(0,255))

    return key

def encryption_oracle(data):
    key = gen_AES_key()
    prebytes = randint(5,10)
    postbytes = randint(5,10)
    encr_type = randint(0,1)
    encry = bytes()

    data = gen_AES_key(prebytes) + bytes(data, 'ascii') + gen_AES_key(postbytes)

    if encr_type:
        print("Actual Encryption: CBC")
        encry = cbc_encrypt(data, key, gen_AES_key())
    else:
        print("Actual Encryption: ECB")
        encry = ecb_encrypt(data, key)

    return encry

def ecb_encrypt(data, key):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)
    encry = bytes()

    if len(data)%16 != 0:
        padded_len = 16*(len(data)//16 + 1)
        data = pad(data, padded_len)

    blocks = get_blocks(data)

    encry = cr.encrypt(data)

    return encry

# cbc encrypt with a 16 byte iv and key
def cbc_encrypt(data, key, iv):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    blocks = get_blocks(data)
    prev_block = bytes()
    encry = bytes()

    prev_block = iv
    for block in blocks:
        prev_block = cr.encrypt(xor_encrypt(block, prev_block, False))
        encry += prev_block

    return encry

# cbc decrypt with a 16 byte iv and key
def cbc_decrypt(data, key, iv):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    blocks = get_blocks(data)

    decry = bytes()

    prev_block = iv
    for block in blocks:
        decry += xor_encrypt(cr.decrypt(block), prev_block, False)
        prev_block = block

    return decry

# fills a key to match the size of text its encrypting against
def fill_key(block, key):
    pad = len(block)//len(key)
    extpad = len(block)%len(key)

    return key*pad + key[:extpad]

def get_blocks(data, size=16):
  if len(data)%size != 0:
    padded_len = size*(len(data)//size + 1)
    data = pad(data, padded_len)

  # divide data in size chunks
  num_blocks = len(data)//size

  blocks = []
  for i in range(0, num_blocks):
    st = i*size
    blocks.append(data[st:st+size])

  return blocks

# xors bytes against a key
def xor_encrypt(block, key, pad=True):
    if pad:
        key = fill_key(key, block)

    return bytes([a^b for (a,b) in zip(key, block)])

# pads bytes() to make sure they're of equal length
def pad(block, length):
  pad_length = length - len(block)
  padding = b'\x04'

  if pad_length:
    return block + (padding*pad_length)
  else:
    return block

def detect_ecb(data, block_size):
    blocks = []
    print(data)
    print()

    for x in range(0,len(data), block_size):
        blocks.append( data[x:x+block_size] )
        print( data[x:x+block_size])
        cn = Counter(blocks)

    if cn.most_common()[0][1] > 1:
        return data
    else:
        pass

    return b''

def test_cbc(data, key, iv):
    enc = cbc_encrypt(data, key, iv)
    print(enc)
    dec = cbc_decrypt(enc, key, iv)
    print(dec.decode('ascii'))

def main():
    text = "DOLLA DOLLA BILLDOLLA DOLLA BILLDOLLA DOLLA BILLDOLLA DOLLA BILLDOLLA DOLLA BILL"

    enc = encryption_oracle(text)

    if(detect_ecb(enc, 16)):
        print('Predicted encryption: ECB')
    else:
        print('Predicted encryption: CBC')

if __name__ == '__main__':
    main()
