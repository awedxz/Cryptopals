import binascii
from Crypto.Cipher import AES
import base64
import struct
import re
from random import randint

k = b''

def gen_AES_key(length=16):
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

# cbc encrypt with a 16 byte iv and key
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
def xor_encrypt(block, key, pad=False):
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

def encrypt_txt(txt):
    global k
    iv = b'\x00' * 16
    txt = "comment1=cooking%20MCs;userdata=" + txt + ";comment2=%20like%20a%20pound%20of%20bacon"
    escaped = txt.replace(';', '";"').replace('=', '"="')
    enc = cbc_encrypt(bytes(escaped,'ascii'),k ,iv)

    return enc

def check_admin(data):
    global k
    iv = b'\x00' * 16
    txt = cbc_decrypt(data,k,iv).decode('ascii', 'ignore')
    admin = "admin=true"

    if admin in txt:
        return True

    return False

def main():
    global k
    k = gen_AES_key()

    """

      escaped blocks:

            comment1"="cooki
            ng%20MCs";"userd
            ata"="";"adminxt
            rue";"comment2"=

    """
    enc = bytearray(encrypt_txt(";admin true;"))

    first_block = enc[:16]
    second_block = enc[16:32]
    the_rest = enc[32:]

    # from ' ' to =
    second_block[14] = second_block[14] ^ ord(" ") ^ ord("=")
    new_enc = bytes(first_block + second_block + the_rest)

    print(check_admin(new_enc))


if __name__ == '__main__':
    main()
