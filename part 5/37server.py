from flask import Flask, request, jsonify
from Crypto.Hash import SHA256, HMAC
from time import sleep
from random import randint

app = Flask(__name__)

I = b''
P = b''
K = b''
uH = b''
N = 0
g = 0
k = 0
v = 0
u = 0
B = 0
A = 0
S = 0
salt = randint(1, 0xFFFFFFFF)
b = randint(1, 0xFFFFFFFF)

def init():
    global salt, v, g, N, k, I, P
    N = int(request.args.get('N'))
    g = int(request.args.get('g'))
    k = int(request.args.get('k'))
    I = bytes(request.args.get('I'), 'ascii')
    P = bytes(request.args.get('P'), 'ascii')
    h = SHA256.new()
    h.update(bytes(format(salt, 'x'), 'ascii') + P)
    xH = h.hexdigest()
    x = int(xH, 16)
    v = fast_pow(g, x, N)

def calc_uH(A, B):
    global u, uH
    hasher = SHA256.new()
    hasher.update(bytes(format(A, 'x'), 'ascii') + bytes(format(B, 'x'), 'ascii'))
    uH = hasher.hexdigest()
    u = int(uH, 16)

def calc_SK():
    global S, A, v, u, N, b, K
    S = fast_pow(A * fast_pow(v, u, N), b, N)
    hasher = SHA256.new()
    hasher.update(bytes(format(S, 'x'), 'ascii'))
    K = hasher.hexdigest()

def start():
    global I, A, salt, B, k, v, g, b, N
    I = bytes(request.args.get('I'), 'ascii')
    A = int(request.args.get('A'))
    B = (k * v) + fast_pow(g, b, N)
    calc_uH(A, B)
    calc_SK()
    resp = {'B': B, 'salt': salt}
    return jsonify(**resp)

def check_hmac():
    global K, salt
    key = bytes(K, 'ascii')
    msg = bytes(format(salt, 'x'), 'ascii')
    hasher = HMAC.new(key, digestmod=SHA256)
    hasher.update(msg)
    hmac = hasher.hexdigest()
    client_hmac = request.args.get('hmac')
    resp = {'status': 'BAD'}
    if (hmac == client_hmac):
        resp['status'] = 'OK'
    return jsonify(**resp)

def fast_pow(x, y, z):
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

@app.route("/crypto")
def crypto():
    method = request.args.get('method')
    if method == 'init':
        init()
    if method == 'start':
        return start()
    if method == 'hmac_check':
        return check_hmac()

if __name__ == "__main__":
    app.run(port=8081, debug=True)
