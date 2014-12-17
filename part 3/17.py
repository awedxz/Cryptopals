from binascii import hexlify, unhexlify
import sys
import struct
from Crypto.Cipher import AES
from random import randint

class PaddingException(Exception):
    pass

ran_strings = [
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]
aes_key = b''
iv = b'\x00' * 16

def pick_string():
    x = bytes(ran_strings[randint(0,9)], 'ascii')
    print(x)
    global aes_key
    aes_key = gen_AES_key() if aes_key == b'' else aes_key

    y = cbc_encrypt(x, aes_key, iv)

    return y, iv


def check_padding(cipher, iv):
    x = cbc_decrypt(cipher, aes_key, iv)

    try:
        validate_pks7(x)
        return True
    except PaddingException:
    	return False
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise

def validate_pks7(txt):
    length = 0

    pks7_padding = txt[-1]
    padding = txt[-pks7_padding:]

    for i in padding:
        if i != pks7_padding:
            raise PaddingException('Invalid PKS#7 padding')

    return txt[:-pks7_padding]


def gen_AES_key(length=16):
    key = bytes()
    for i in range(length):
        key += struct.pack('B', randint(0,255))

    return key


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

    blocks = get_blocks(data, False)

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


def get_blocks(data, pad_it=True, size=16):
    if pad_it:
        padded_len = size*(len(data)//size + 1)
        data = pad(data, padded_len)

    # divide data in size chunks
    num_blocks = len(data)//size + 1

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
  padding = pad_length.to_bytes(1, byteorder='big')

  if pad_length:
    return block + (padding * pad_length)
  else:
    return block

def test():
    data = b'A'
    key = gen_AES_key()
    iv = b'\x00'*16

    for i in range(1, 17):
        data = b'A' * i

        a = cbc_encrypt(data, key, iv)
        b = cbc_decrypt(a, key, iv)
        c = validate_pks7(b)

        assert data == c


def main():
    try:
        test()
    except AssertionException:
        return;

    ciphertext, iv = pick_string()
    plaintext = ''
    block_size = len(iv)

    # break cipher into blocks
    cipher_blocks = []
    for i in range(1, int(len(ciphertext)/block_size)+1):
        cipher_blocks.append(ciphertext[(i-1)*block_size:i*block_size])

    cipher_blocks.insert(0, iv)

    for block in range(len(cipher_blocks)-1, 0, -1):
        nextvals = []

        for byte_num in range(1, block_size + 1):
            fake = b'\x00' * (block_size - byte_num)
            found = False

            for i in range(0, 255):
                item = i.to_bytes(1, byteorder='big')
                fake_block = fake + item + b''.join(nextvals) + cipher_blocks[block]
                if check_padding(fake_block, iv):
                    found = True
                    break

            if not found:
                print ("[-] Error: No correct padding found!")
                return

            pre_xor_val = byte_num ^ int.from_bytes(item, byteorder='big')
            plainchar = pre_xor_val ^ cipher_blocks[block - 1][block_size - byte_num]
            plaintext = chr(plainchar) + plaintext

            for i in range(0, len(nextvals)):
                nextvals[i] = (int.from_bytes(nextvals[i], byteorder='big') ^ byte_num ^ (byte_num + 1)).to_bytes(1, byteorder='big')

            nextvals.insert(0, (pre_xor_val ^ (byte_num + 1)).to_bytes(1, byteorder='big'))

    print(plaintext)


if __name__ == '__main__':
    main()
