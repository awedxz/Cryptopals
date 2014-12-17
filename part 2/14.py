import base64
import struct
import string
from Crypto.Cipher import AES
from random import randint
from collections import Counter

k = b''
random_prefix = ''.join([chr(randint(0,127)) for i in range(randint(0, 16))])

def gen_AES_key(length=16):
    key = bytes()
    for i in range(length):
        key += struct.pack('B', randint(0,255))

    return key

def encryption_oracle(data):
    global k
    global random_prefix

    # string value to discover
    append_string = base64.b64decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSBy"
                                     b"YWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4g"
                                     b"YmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5"
                                     b"IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQg"
                                     b"eW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                     b"YnkK")

    data_bytes = bytes(data, 'ascii')
    data_bytes = bytes(random_prefix, 'ascii') +data_bytes + append_string

    encry = ecb_encrypt(data_bytes, k)
    return encry

def ecb_encrypt(data, key, size=16):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    if len(data)%size != 0:
        padded_len = size*(len(data)//size + 1)
        data = pad(data, padded_len)

    encry = cr.encrypt(data)

    return encry

# pads bytes() to make sure they're of equal length
def pad(block, length):
  pad_length = length - len(block)
  padding = b'\x04'

  if pad_length:
    return block + (padding*pad_length)
  else:
    return block

def find_random(block_size):
    for x in range(block_size+1):
        tst_str = "A" * x
        tst = encryption_oracle(tst_str)
        if x == 0:
            pass
        elif tst[0:16] == past_tmp:
            return 16-(x-1)
        past_tmp = tst[0:16]

def main():
    global k
    k = gen_AES_key()
    possible_letters = string.printable

    match_list = []

    # 1. determine block size
    # (detect by finding when the padding "jumps" to the next multiple)
    for i in range(32):
        block = "A" * (i+1)
        enc = encryption_oracle(block)
        temp_size = len(enc)
        if i == 0:
            hidden_size = temp_size
            block_size = temp_size

        if temp_size != block_size:
            block_size = abs(temp_size - block_size)
            break

    # left out ECB check here, easy to put back in
    random_size = find_random(block_size)

    for size in range((hidden_size-1), -1,  -1):
        input_block = 'A'*(block_size - random_size) + 'A'*size #craft input of n - 1 (plus 'padding' for randoms)
        dict_key = encryption_oracle(input_block) # (returns [RANDOM](AAAA[hiddenitem])[restofenc][padding])

        for char in possible_letters:
            input_string = input_block + ''.join(match_list) + char
            if encryption_oracle(input_string)[block_size:hidden_size+block_size] == dict_key[block_size:hidden_size+block_size]:
                match_list.append(char)
                break

        if len(match_list) + size <= hidden_size - 1:
            print("No match found at", size)
            break


    print("Hidden string:", ''.join(match_list))

if __name__ == '__main__':
    main()
