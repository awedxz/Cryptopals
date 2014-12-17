import binascii
from Crypto.Cipher import AES
import base64
import struct
import re
from random import randint

def gen_key(length=16):
    key = bytes()
    for i in range(length):
        key += struct.pack('B', randint(0,255))

    return key

def validiate_pks7(txt):
    count = 0
    for i in range(len(txt)-1, 0, -1):
        if ord(txt[i]) < 32 or ord(txt[i]) > 126 or ord(txt[i]) == 9 or ord(txt[i]) == 10 or ord(txt[i]) == 13:
            if txt[i] != '\x04':
                raise Exception('Invalid PKS#7 padding')
            else:
                count += 1
    stripped = txt[:-count]
    return stripped

def cbc_encrypt(data, key, iv):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    blocks = get_blocks(data)
    prev_block = bytes()
    encry = bytes()

    prev_block = iv
    for block in blocks:
        prev_block = cr.encrypt(xor_encrypt(block, prev_block))
        encry += prev_block

    return encry

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

def fill_key(block, key):
    pad = len(block)//len(key)
    extpad = len(block)%len(key)

    return key*pad + key[:extpad]

def get_blocks(data, size=16):
  if len(data)%size != 0:
    padded_len = size*(len(data)//size + 1)
    data = pad(data, padded_len)

  num_blocks = len(data)//size

  blocks = []
  for i in range(0, num_blocks):
    st = i*size
    blocks.append(data[st:st+size])

  return blocks

def xor_encrypt(block, key, pad=False):
    if pad:
        key = fill_key(key, block)

    return bytes([a^b for (a,b) in zip(key, block)])

def pad(block, length):
  pad_length = length - len(block)
  padding = b'\x04'

  if pad_length:
    return block + (padding*pad_length)
  else:
    return block

def main():
    k = gen_key()
    iv = k
    pt = b"thisisthreeblockslongthisisthreeblockslongthisis"
    ct = cbc_encrypt(pt, k, iv)
    attacker_intercept = b''

    # attacker
    ct = ct[:16] + (b'\x00' * 16) + ct[:16]

    # receiver
    new_pt = cbc_decrypt(ct, k, iv)

    # throw error if high-ascii found
    try:
        new_pt.decode('ascii')
    except:
        print('Exception! Bad decryption: ', new_pt)
        attacker_intercept = new_pt

    # attacker
    key = xor_encrypt(attacker_intercept[0:16], attacker_intercept[32:48])
    print(key == k)

if __name__ == '__main__':
    main()