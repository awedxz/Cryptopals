'''
Implement Secure Remote Password (SRP)
'''

from random import randint
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
from struct import pack

class ClientServer:
    def __init__(self):
        self.N = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
        self.g = 2
        self.k = 3
        self.I = b''
        self.P = b''
        self.ack = False
        self.a = randint(1, 0xFFFFFFFF)
        self.b = randint(1, 0xFFFFFFFF)
        self.A = 0
        self.I = b''
        self.B = 0
        self.u = 0
        self.uH = b''
        self.S = 0
        self.K = 0
        self.hmac_valid = False
        self.v = 0

    def update_key(self, N, g, k, I, P):
        self.N = N
        self.g = g
        self.k = k
        self.I = I
        self.P = P
        self.salt = randint(1, 0xFFFFFFFF)
        h = SHA256.new()
        h.update(bytes(format(self.salt, 'x'), 'ascii') + self.P)
        xH = h.hexdigest()
        x = int(xH, 16)
        self.v = fast_pow(self.g, x, self.N)

    def init(self, email, password):
        self.I = email
        self.P = password
        return ('init', self.N, self.g, self.k, self.I, self.P)

    def start(self):
        self.A = fast_pow(self.g, self.a, self.N)
        return ('start', self.I, self.A)

    def conn_start(self, I, A):
        self.A = A
        self.I = I
        self.B = (self.k * self.v) + fast_pow(self.g, self.b, self.N)

    def calc_uHu(self):
        # S, C
        # Compute string uH = SHA256(A|B), u = integer of u
        hasher = SHA256.new()
        hasher.update(bytes(format(self.A, 'x'), 'ascii') + bytes(format(self.B, 'x'), 'ascii'))
        self.uH = hasher.hexdigest()
        self.u = int(self.uH, 16)

    def calc_xHSK(self):
        # Generate string xH=SHA256(salt|password)
        # Convert xH to integer x somehow (put 0x on hexdigest)
        # Generate S = (B - k * g**x)**(a + u * x) % N
        # Generate K = SHA256(S)
        hasher = SHA256.new()
        hasher.update(bytes(format(self.salt, 'x'), 'ascii') + self.P)
        xH = hasher.hexdigest()
        x = int(xH, 16)
        self.S = fast_pow(self.B - self.k * fast_pow(self.g, x, self.N), self.a + self.u * x, self.N)
        hasher = SHA256.new()
        hasher.update(bytes(format(self.S, 'x'), 'ascii')) # fuck python3
        self.K = hasher.hexdigest()


    def compare_hmac(self, otherhmac):
        hasher = HMAC.new(bytes(self.K, 'ascii'), bytes(format(self.salt, 'x'), 'ascii'), SHA256)
        hmac = hasher.hexdigest()
        if hmac == otherhmac:
            self.hmac_valid = True

    def receive(self, msg):
        if msg[0] == 'init':
            self.update_key(msg[1], msg[2], msg[3], msg[4], msg[5])
        elif msg[0] == 'start':
            self.conn_start(msg[1], msg[2])
        elif msg[0] == 'salt':
            self.salt = msg[1]
            self.B = msg[2]
        elif msg[0] == 'hmac':
            self.compare_hmac(msg[1])
        elif msg[0] == 'ACK':
            self.ack = True;


def fast_pow(x, y, z):
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

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
    client = ClientServer()
    server = ClientServer()

    # C & S
    # Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    send(client.init(b'email', b'password'), server)
    server.ack = True
    send(('ACK',), client) # 'agreement'

    # C->S
    # Send I, A=g**a % N (a la Diffie Hellman)
    send(client.start(), server)

    #S->C
    #Send salt, B=kv + g**b % N
    send(('salt', server.salt, server.B), client)

    # S, C
    # Compute string uH = SHA256(A|B), u = integer of uH
    server.calc_uHu()
    client.calc_uHu()

    # C
    # Generate string xH=SHA256(salt|password)
    # Convert xH to integer x somehow (put 0x on hexdigest)
    # Generate S = (B - k * g**x)**(a + u * x) % N
    # Generate K = SHA256(S)
    client.calc_xHSK()

    # S
    # Generate S = (A * v**u) ** b % N
    # Generate K = SHA256(S)
    server.S = fast_pow(server.A * fast_pow(server.v, server.u, server.N), server.b, server.N)
    hasher = SHA256.new()
    hasher.update(bytes(format(server.S, 'x'), 'ascii'))
    server.K = hasher.hexdigest()

    # C->S
    # Send HMAC-SHA256(K, salt)
    key = bytes(client.K, 'ascii')
    msg = bytes(format(client.salt, 'x'), 'ascii')
    hasher = HMAC.new(key, digestmod=SHA256)
    hasher.update(msg)
    hmac = hasher.hexdigest()
    send(('hmac', hmac), server)

    # S->C
    # Send "OK" if HMAC-SHA256(K, salt) validates
    if server.hmac_valid:
        send(('OK',), client)
        print('win')

if __name__ == '__main__':
    main()
