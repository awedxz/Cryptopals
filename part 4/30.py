'''
Break an MD4 keyed MAC using length extension
Second verse, same as the first, but use MD4 instead of SHA-1.
Having done this attack once against SHA-1, the MD4 variant should
take much less time; mostly just the time you'll spend Googling for
an implementation of MD4.

You're thinking, why did we bother with this?
Blame Stripe. In their second CTF game, the second-to-last challenge
involved breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code
was floating all over the Internet. MD4 code, not so much.
'''

from Crypto.Cipher import AES
from struct import pack, unpack
from random import randint
import random
from md4.md4 import MD4
from md4.U32 import U32

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

def sha_auth(key, mess):
    return sha1(key + mess)

def compute_md_padding(msg):
    original_byte_len = len(msg)
    original_bit_len = original_byte_len * 8

    msg += b'\x80'
    msg += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    msg += pack(b'<Q', original_bit_len)

    return msg[original_byte_len:]

def main():
    pt = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    pt_add = b";admin=true"
    md4er = MD4()

    WORDS = ["hi", "cat", "dog",
             "animal", "inspect", "insect",
             "also", "cryptography", "justin",
             "long", "the", "at"]

    word = bytes(random.choice(WORDS).encode('ascii'))
    md4er.update(word + pt)
    spmac = md4er.digest()

    a = U32(unpack("<L", spmac[:4])[0])
    b = U32(unpack("<L", spmac[4:8])[0])
    c = U32(unpack("<L", spmac[8:12])[0])
    d = U32(unpack("<L", spmac[12:16])[0])

    padding = compute_md_padding(word + pt)
    new_md4 = MD4()
    new_md4.update(word + pt + padding + pt_add)
    legit_admin = new_md4.digest()
    win = False

    for i in range(32):
        filler = b'A' * i
        og_pad = compute_md_padding(filler + pt)
        combined = filler + pt + og_pad

        newer_md4 = MD4()
        newer_md4.update(combined) # get length state to the correct place

        newer_md4.A = a
        newer_md4.B = b
        newer_md4.C = c
        newer_md4.D = d

        newer_md4.update(pt_add)

        forgery = newer_md4.digest()

        if (forgery == legit_admin):
            win = True
            break

    print(win)

if __name__ == '__main__':
    main()
