import binascii
import base64
import struct
import string
from Crypto.Cipher import AES
from random import randint
from collections import Counter

k = b''

class User:
    email = ''
    uid = 10
    role = 'user'
    def set_email(self, email):
        self.email = email
    def set_uid(self, uid):
        self.uid = uid
    def set_role(self, role):
        self.role = role
    def __str__(self):
        return 'email='+self.email+'&uid='+self.uid+'&role='+self.role

def gen_AES_key(length=16):
    key = bytes()
    for i in range(length):
        key += struct.pack('B', randint(0,255))

    return key

def ecb_encrypt(data, key, size=16):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    if len(data)%size != 0:
        padded_len = size*(len(data)//size + 1)
        data = pad(data, padded_len)

    encry = cr.encrypt(data)

    return encry

def ecb_decrypt(data, key, size=16):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    if len(data)%size != 0:
        padded_len = size*(len(data)//size + 1)
        data = pad(data, padded_len)

    decry = cr.decrypt(data)

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

def key_val(string):
    pairs = string.split('&')
    user = User()
    for pair in pairs:
        pair = pair.split('=')
        if pair[0] == 'email':
            user.set_email(pair[1])
        elif pair[0] == 'uid':
            user.set_uid(pair[1])
        elif pair[0] == 'role':
            user.set_role(pair[1])

    return user

def profile_for(email):
    metachars = '!#$%^&*()_+=-[]}{:\"\'<>?/,'

    for metachar in metachars:
        if metachar in email:
            split_email = email.split(metachar)
            for part in split_email:
                if '@' in part:
                    email = part

    profile_string = 'email=' + ''.join(email) + '&uid=10&role=user'
    return key_val(profile_string)

def encode_profile(profile_obj):
    return profile_obj.__str__()

def encrypt_profile(profile_string):
    global k
    bytes_string = bytes(profile_string, 'ascii')
    return ecb_encrypt(bytes_string, k)

#beautifully ugly profile encryption function
# returns ECB encrypted string
def profile_oracle(plaintext_email):
    return encrypt_profile(encode_profile(profile_for(plaintext_email)))

# beautifully ugly decryption function
# returns a profile object
def decrypt_profile(encrypted_profile):
    global k
    return key_val(depad(ecb_decrypt(encrypted_profile, k)).decode('ascii')).__str__()

def depad(string):
    return string.replace(b'\x04', b'')

def main():
    global k
    k = gen_AES_key()

    admin = "jur@oblak.admin" + ("\x04" * 11)
    user = "jroblak@o.com"

    encadmin  = profile_oracle(admin)
    encuser  = profile_oracle(user)

    # take user profile minus last bytes ('user' + \x04 * 12)
    # gives us encrypted: "email=[13 byte email]&uid=10&role="
    admin_user = encuser[:-16]

    # take the encrypted 'admin' chunk of the first block (user input)
    # and add it to end of our user profile
    admin_user += encadmin[16:32]

    hacked_profile = decrypt_profile(admin_user)
    print(hacked_profile)


if __name__ == '__main__':
    main()
