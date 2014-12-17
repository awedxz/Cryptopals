from random import randint
from Crypto.Hash import SHA256, HMAC
import requests

class Client:
    def __init__(self):
        # inital agreement (registration?)
        self.N = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
        self.g = 2
        self.k = 3
        self.I = b'jroblak'
        self.P = b'userpassword123'
        # other vars
        self.a = randint(1, 0xFFFFFFFF)
        self.A = 0
        self.B = 0
        self.u = 0
        self.uH = ''
        self.S = 0
        self.K = 0
        self.v = 0

    def init_agreement(self):
        return {'method': 'init', 'N': self.N, 'g': self.g, 'k': self.k, 'I': self.I, 'P': self.P}

    def start(self):
        self.A = fast_pow(self.g, self.a, self.N)
        return {'method': 'start', 'I': self.I, 'A': self.A}

    def calc_uHu(self):
        hasher = SHA256.new()
        hasher.update(bytes(format(self.A, 'x'), 'ascii') + bytes(format(self.B, 'x'), 'ascii'))
        self.uH = hasher.hexdigest()
        self.u = int(self.uH, 16)

    def calc_xHSK(self):
        hasher = SHA256.new()
        hasher.update(bytes(format(self.salt, 'x'), 'ascii') + self.P)
        xH = hasher.hexdigest()
        x = int(xH, 16)
        self.S = fast_pow(self.B - self.k * fast_pow(self.g, x, self.N), self.a + self.u * x, self.N)
        hasher = SHA256.new()
        hasher.update(bytes(format(self.S, 'x'), 'ascii')) # fuck python3
        self.K = hasher.hexdigest()

    def hmac(self):
        key = bytes(self.K, 'ascii')
        msg = bytes(format(self.salt, 'x'), 'ascii')
        hasher = HMAC.new(key, digestmod=SHA256)
        hasher.update(msg)
        hmac = hasher.hexdigest()
        return {'method': 'hmac_check', 'hmac': hmac}

def fast_pow(x, y, z):
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

def normal():
    client = Client()
    r = requests.get('http://127.0.0.1:8081/crypto', params = client.init_agreement())
    r = requests.get('http://127.0.0.1:8081/crypto', params = client.start())
    resp = r.json()
    client.salt = resp['salt']
    client.B = resp['B']
    client.calc_uHu()
    client.calc_xHSK()
    r = requests.get('http://127.0.0.1:8081/crypto', params = client.hmac())
    if r.json()['status'] == 'OK':
        return True
    return False

def azero():
    client = Client()

    initial = client.init_agreement()
    initial["P"] = b''
    r = requests.get('http://127.0.0.1:8081/crypto', params = initial)

    tampered = client.start()
    tampered["A"] = 0
    r = requests.get('http://127.0.0.1:8081/crypto', params = tampered)

    resp = r.json()
    client.salt = resp['salt']
    client.B = resp['B']
    client.calc_uHu()
    client.calc_xHSK()

    hasher = SHA256.new()
    hasher.update(bytes(format(0, 'x'), 'ascii'))
    client.K = hasher.hexdigest()

    r = requests.get('http://127.0.0.1:8081/crypto', params = client.hmac())
    if r.json()['status'] == 'OK':
        return True
    return False

def main():
    assert(normal() == True)
    assert(azero() == True)
    '''Now log in without your password by having the client send N, N*2, &c.'''
    client = Client()

    initial = client.init_agreement()
    initial["P"] = b''
    r = requests.get('http://127.0.0.1:8081/crypto', params = initial)

    tampered = client.start()
    tampered["A"] = client.N
    '''
    S = (A * (v ** u % N)) ** b % N
    S = (A * x) ^ y % A
    S = 0 -- any multiple of A raised to anything modulo A == 0
    '''
    r = requests.get('http://127.0.0.1:8081/crypto', params = tampered)

    resp = r.json()
    client.salt = resp['salt']
    client.B = resp['B']
    client.calc_uHu()
    client.calc_xHSK()

    hasher = SHA256.new()
    hasher.update(bytes(format(0, 'x'), 'ascii'))
    client.K = hasher.hexdigest()

    r = requests.get('http://127.0.0.1:8081/crypto', params = client.hmac())
    if r.json()['status'] == 'OK':
        print('win')

if __name__ == '__main__':
    main()
