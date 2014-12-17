import binascii
import base64
import struct
import string
from Crypto.Cipher import AES
from random import randint
from collections import Counter

k = b''

def gen_AES_key(length=16):
    key = bytes()
    for i in range(length):
        key += struct.pack('B', randint(0,255))

    return key

def encryption_oracle(data):
    global k

    # string value to discover
    append_string = base64.b64decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSBy"
                                     b"YWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4g"
                                     b"YmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5"
                                     b"IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQg"
                                     b"eW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                     b"YnkK")

    data_bytes = bytes(data, 'ascii')
    data_bytes = data_bytes + append_string

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

def detect_ecb(data, block_size=16):
    blocks = []

    for x in range(0,len(data), block_size):
        blocks.append( data[x:x+block_size] )
        cn = Counter(blocks)

    if cn.most_common()[0][1] > 1:
        return data
    else:
        pass

    return b''

def main():
    global k
    k = gen_AES_key()
    possible_letters = string.printable
    match_list = []

    print() #spacing

    # 1. determine block size (16), s by feeding blocks one at a time
    # (detect by finding when the padding "jumps" to the next multiple)
    for i in range(30):
        block = "A" * (i+1)
        enc = encryption_oracle(block)
        temp_size = len(enc)
        if i == 0:
            hidden_size = temp_size
            block_size = temp_size

        elif temp_size != block_size:
            block_size = temp_size - block_size
            break
    print("Found block size of:", block_size)
    print("Found hidden size of:", hidden_size)
    print()

    # 2. detect ECB
    # (using obviously repeating data)
    ecb_detect_string = "DATADATADATADATADATADATADATADATADATADATADATADATADATADATADATA"
    if detect_ecb(encryption_oracle(ecb_detect_string), 16):
        print('ECB Detected')
    else:
        print('No ECB :(')

    print()

    # 3. make input block of (s - 1)
    # 3.5 run 1 byte short block through oracle function (nth byte fills the empty spot)
    # 4. run over every possible last byte (i.e. AAAAAAAA - AAAAAAAZ)
    # 5. match output of one byte-short input to one of dictionary entries
    # 6. repeat for next byte
    for size in range((hidden_size-1), -1, -1):
        input_block = "A" * size

        dict_key = encryption_oracle(input_block)

        for char in possible_letters:
            input_string = input_block + ''.join(match_list) + char
            if encryption_oracle(input_string)[:hidden_size] == dict_key[:hidden_size]:
                match_list.append(char)
                break

        if len(match_list) + size <= 15:
            print("No match found at", size)
            print("Breaking")
            break


    print("Hidden string:", ''.join(match_list))

if __name__ == '__main__':
    main()
