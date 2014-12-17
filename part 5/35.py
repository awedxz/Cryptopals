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
        self.ack = False

    def update_key(self, p, g):
        self.p = p
        self.g = g
        self.public_key = pow(g, self.secret, p)

    def init_send(self):
        return ('init', self.p, self.g)

    def send_msg(self, msg):
        iv = gen_key()
        return cbc_encrypt(msg, self.key[:16], iv) + iv 

    def compute_hash(self, publickey):
        s = pow(publickey, self.secret, self.p)
        string = format(s, 'x')

        while len(string) % 4 != 0:
            string = '0' + string

        hash = SHA.new()
        hash.update(bytes.fromhex(string))
        self.key = hash.hexdigest()

    def receive(self, msg):
        if msg[0] == 'init':
            self.update_key(msg[1], msg[2])
        elif msg[0] == 'publickey':
            self.compute_hash(msg[1])
        elif msg[0] == 'ACK':
            self.ack = True;
        else:
            iv = msg[-16:]
            return cbc_decrypt(msg, self.key[:16], iv)

class BadPerson:
    def __init__(self, name):
        self.p = 0
        self.g = 0
        self.last_key = -1
        self.first_key = -1
        self.public_key = 0
        self.last_msg = b''
        self.name = name
        self.key = 0
        self.key_broken = False

    def update(self, p, g):
        self.p = p
        self.g = g

    def bad_init(self):
        return ('init', self.p, self.g)

    def break_msg(self, msg):
        if not self.key_broken: 
            self.break_hash(msg)
            self.key_broken = True
        
        return cbc_decrypt(msg, self.key[:16], msg[-16:])

    def break_hash(self, msg):
        publickey = 0

        # ugly
        if (self.p - 1) == self.g:
            if self.last_key != 1:
                if self.first_key == 1:
                    publickey = 1
                else:
                    publickey = self.last_key
            else:
                publickey = 1
        if self.g == 1:
            publickey = 1

        s = publickey # 1 ^ x == 1; 1 % x == 1; 0 ^ x == 0; 0 % x == 0; 

        iv = msg[-16:]
        string = format(s, 'x')

        while len(string) % 4 != 0:
            string = '0' + string

        hash = SHA.new()
        hash.update(bytes.fromhex(string))
        self.key = hash.hexdigest()

    def receive(self, msg):
        if msg[0] == 'init':
            self.update(msg[1], msg[2])
        elif msg[0] == 'publickey':
            if self.first_key == -1:
                self.first_key = msg[1]
            self.last_key = msg[1]
        elif msg[0] == 'ACK':
            self.ack = True;
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

def xchange(gval):
    alice = Person('alice')
    bob = Person('bob')
    mitm = BadPerson('mitm')

    send(alice.init_send(), mitm) # A -> M (p, g)
    mitm.g = gval
    alice.update_key(alice.p, gval)
    send(mitm.bad_init(), bob) # M -> B (p, g)

    send(('ACK',), mitm) # B -> M (ACK)
    send(('ACK',), alice) # M -> A (ACK)

    send(('publickey', alice.public_key), mitm) # A -> M (A)
    send(('publickey', mitm.last_key), bob) # M -> B (A)

    send(('publickey', bob.public_key), mitm) # B -> M (B)
    send(('publickey', mitm.last_key), alice) # M -> A (B)

    x = send(alice.send_msg(b'message'), mitm) # A -> M (enc(msg))
    y = send(mitm.last_msg, bob) # M -> B (enc(msg))

    a = send(bob.send_msg(x), mitm) # B -> M (enc(A's msg))
    b = send(mitm.last_msg, alice) # M -> A (end(msg))

    assert(x == y)
    assert(a == b)

def main():
    #xchange(1)  # public key == 1
    # v g == p => public key == 0
    #xchange(0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff)
    # public key == 1 (or g if secret is odd)
    xchange(0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff - 1)

if __name__ == '__main__':
    main()
