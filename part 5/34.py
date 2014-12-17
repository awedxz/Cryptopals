from random import randint
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from struct import pack

class Person:
    def __init__(self, name):
        self.secret = randint(0, 0xFFFFFFFF) % 37
        self.p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
        self.g = 2
        self.public_key = (self.g ** self.secret) % self.p
        self.key = b''
        self.name = name

    def update_key(self, p, g):
        self.public_key = (g ** self.secret) % p

    def init_send(self):
        return ('init', self.p, self.g, self.public_key)

    def send_msg(self, msg):
        iv = gen_key()
        return cbc_encrypt(msg, self.key[:16], iv) + iv 

    def compute_hash(self, publickey):
        s = (publickey ** self.secret) % self.p
        string = format(s, 'x')

        while len(string) % 4 != 0:
            string = '0' + string

        hash = SHA.new()
        hash.update(bytes.fromhex(string))
        self.key = hash.hexdigest()

    def receive(self, msg):
        if msg[0] == 'init':
            self.update_key(msg[1], msg[2])
            self.compute_hash(msg[3])
        elif msg[0] == 'publickey':
            self.compute_hash(msg[1])
        else:
            iv = msg[-16:]
            return cbc_decrypt(msg, self.key[:16], iv)

class BadPerson:
    def __init__(self, name):
        self.p = 0
        self.g = 0
        self.A = 0
        self.B = 0
        self.public_key = 0
        self.last_msg = b''
        self.name = name
        self.key = 0
        self.key_broken = False

    def update(self, p, g, A):
        self.p = p
        self.g = g
        self.A = A

    def bad_init(self):
        return ('init', self.p, self.g, self.p)

    def break_msg(self, msg):
        if not self.key_broken: # thought this would be harder...
            self.break_hash(msg) # ... (x ^ y) % x === 0
            self.key_broken = True
        
        return cbc_decrypt(msg, self.key[:16], msg[-16:])

    def break_hash(self, msg):
        s = 0
        iv = msg[-16:]
        string = format(s, 'x')

        while len(string) % 4 != 0:
            string = '0' + string

        hash = SHA.new()
        hash.update(bytes.fromhex(string))
        self.key = hash.hexdigest()

    def receive(self, msg):
        if msg[0] == 'init':
            self.update(msg[1], msg[2], msg[3])
        elif msg[0] == 'publickey':
            self.B = msg[1]
        else:
            self.last_msg = msg
            return self.break_msg(msg)

def gen_key(length = 16):
    key = bytes()

    for i in range(length):
        key += pack('B', randint(0,255))

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

def send(data, to):
    return to.receive(data)

def main():
    alice = Person('alice')
    bob = Person('bob')

    send(alice.init_send(), bob)
    send(('publickey', bob.public_key), alice)
    assert(alice.key == bob.key)

    alice = Person('alice')
    bob = Person('bob')
    mitm = BadPerson('mitm')

    # swapping out A and B with 'p' increases the key predictability dramatically
    send(alice.init_send(), mitm) # A -> M (p, g, A)
    send(mitm.bad_init(), bob) # M -> B (p, g, p)
    send(('publickey', bob.public_key), mitm) # B -> M (B)
    send(('publickey', mitm.p), alice) # M -> A (p)

    x = send(alice.send_msg(b'message'), mitm) # A -> M (enc(msg))
    y = send(mitm.last_msg, bob) # M -> B (enc(msg))
    a = send(bob.send_msg(x), mitm) # B -> M (enc(A's msg))
    b = send(mitm.last_msg, alice) # M -> A (end(msg))
    assert(x == y)
    assert(a == b)

if __name__ == '__main__':
    main()
