from Crypto.Cipher import AES
from struct import pack, unpack
from random import randint
import random

def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha1(message, a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476, e = 0xC3D2E1F0, length = -1):
    # Initialize variables:
    h0 = a
    h1 = b
    h2 = c
    h3 = d
    h4 = e
    if length == -1:
        length = len(message)

    # Pre-processing:
    original_byte_len = length
    original_bit_len = original_byte_len * 8

    # append the bit '1' to the message
    message += b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message += pack(b'>Q', original_bit_len)

    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in range(0, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = unpack(b'>I', message[i + j*4:i + j*4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                            a, _left_rotate(b, 30), c, d)

        # sAdd this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian):
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

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

'''
    To implement the attack, first write the function that computes the MD padding
    of an arbitrary message and verify that you're generating the same padding that
    your SHA-1 implementation is using. This should take you 5-10 minutes.
'''
def compute_md_padding(msg):
    original_byte_len = len(msg)
    original_bit_len = original_byte_len * 8

    msg += b'\x80'
    msg += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    msg += pack(b'>Q', original_bit_len)

    return msg[original_byte_len:]

def main():
    pt = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    pt_add = b";admin=true"

    WORDS = ["hi", "cat", "dog",
             "animal", "inspect", "insect",
             "also", "cryptography", "justin",
             "long", "the", "at"]

    word = bytes(random.choice(WORDS).encode('ascii'))
    spmac = bytes.fromhex(sha_auth(word, pt))

    a = unpack(">L", spmac[:4])[0]
    b = unpack(">L", spmac[4:8])[0]
    c = unpack(">L", spmac[8:12])[0]
    d = unpack(">L", spmac[12:16])[0]
    e = unpack(">L", spmac[16:20])[0]

    padding = compute_md_padding(word + pt)
    legit_admin = sha_auth(word, pt + padding + pt_add)
    win = False

    for i in range(32):
        filler = b'A' * i
        og_pad = compute_md_padding(filler + pt)
        combined = filler + pt + og_pad + pt_add
        forgery = sha1(pt_add, a, b, c, d, e, len(combined))
        if (forgery == legit_admin):
            win = True
            break

    print(win)

if __name__ == '__main__':
    main()
