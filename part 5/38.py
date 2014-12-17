from random import randint, choice
from Crypto.Hash import SHA256, HMAC

def fast_pow(x, y, z):
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

def normal():
    N = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
    g = 2
    k = 3
    salt = randint(1, 0xFFFFFFFF)
    P = b'password'
    I = b'username'
    # the lazy way!
    S = {}
    C = {}

    # S
    #x = SHA256(salt|password)
    # v = g**x % n
    S["salt"] = salt
    hasher = SHA256.new()
    hasher.update(bytes(format(salt, 'x'), 'ascii') + P)
    S["x"] = hasher.hexdigest()
    S["v"] = fast_pow(g, int(S["x"], 16), N)

    # C->S
    # I, A = g**a % n
    C["a"] = randint(1, 0xFFFFFFFF)
    C["I"] = I
    S["I"] = C["I"]
    C["A"] = fast_pow(g, C["a"], N)
    S["A"] = C["A"]

    #S->C
    # salt, B = g**b % n, u = 128 bit random number
    S["b"] = randint(1, 0xFFFFFFFF)
    S["B"] = fast_pow(g, S["b"], N)
    S["u"] = randint(1, 0xFFFFFFFFFFFFFFFF)
    C["salt"] = S["salt"]
    C["B"] = S["B"]
    C["u"] = S["u"]

    # C
    # x = SHA256(salt|password)
    # S = B**(a + ux) % n
    # K = SHA256(S)
    hasher = SHA256.new()
    hasher.update(bytes(format(salt, 'x'), 'ascii') + P)
    C["x"] = hasher.hexdigest()
    C["S"] = fast_pow(C["B"], (C["a"] + C["u"] * int(C["x"], 16)), N)
    hasher = SHA256.new()
    hasher.update(bytes(format(C["S"], 'x'), 'ascii'))
    C["K"] = hasher.hexdigest()

    # S
    # S = (A * v ** u)**b % n
    # K = SHA256(S)
    S["S"] = fast_pow(S["A"] * fast_pow(S["v"], S["u"], N), S["b"], N)
    hasher = SHA256.new()
    hasher.update(bytes(format(S["S"], 'x'), 'ascii'))
    S["K"] = hasher.hexdigest()

    # C->S Send HMAC-SHA256(K, salt)
    hasher = HMAC.new(bytes(C["K"], 'ascii'), bytes(format(C["salt"], 'x'), 'ascii'), SHA256)
    C["hmac"] = hasher.hexdigest()

    hasher = HMAC.new(bytes(S["K"], 'ascii'), bytes(format(S["salt"], 'x'), 'ascii'), SHA256)
    S["hmac"] = hasher.hexdigest()

    #S->C Send "OK" if HMAC-SHA256(K, salt) validates
    if S["hmac"] == C["hmac"]:
        return True
    return False

def main():
    assert(normal() == True)
    N = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
    g = 2
    k = 3
    salt = 0
    word_dict = [b'password', b'12345', b'abcdefg', b'test123', b'poc', b'as123434faw',
            b'dog', b'cat', b'atleast15', b'orsomethinglikethat', b'kfjasda', b'badpw',
            b'shadow!!!!']
    P = choice(word_dict)
    I = b'username'
    # the lazy way!
    S = {}
    C = {}

    S["salt"] = salt

    C["a"] = randint(1, 0xFFFFFFFF)
    C["I"] = I
    S["I"] = C["I"]
    C["A"] = fast_pow(g, C["a"], N)
    S["A"] = C["A"]

    S["b"] = 2
    S["B"] = fast_pow(g, S["b"], N)
    S["u"] = 1
    C["salt"] = S["salt"]
    C["B"] = S["B"]
    C["u"] = S["u"]

    hasher = SHA256.new()
    hasher.update(bytes(format(salt, 'x'), 'ascii') + P)
    C["x"] = hasher.hexdigest()
    C["S"] = fast_pow(C["B"], (C["a"] + C["u"] * int(C["x"], 16)), N)
    hasher = SHA256.new()
    hasher.update(bytes(format(C["S"], 'x'), 'ascii'))
    C["K"] = hasher.hexdigest()

    hasher = HMAC.new(bytes(C["K"], 'ascii'), bytes(format(C["salt"], 'x'), 'ascii'), SHA256)
    C["hmac"] = hasher.hexdigest()

    for word in word_dict:
        hasher = SHA256.new()
        hasher.update(bytes(format(salt, 'x'), 'ascii') + word)
        S["x"] = hasher.hexdigest()
        S["v"] = fast_pow(g, int(S["x"], 16), N)

        S["S"] = fast_pow(S["A"] * fast_pow(S["v"], S["u"], N), S["b"], N)
        hasher = SHA256.new()
        hasher.update(bytes(format(S["S"], 'x'), 'ascii'))
        S["K"] = hasher.hexdigest()

        hasher = HMAC.new(bytes(S["K"], 'ascii'), bytes(format(S["salt"], 'x'), 'ascii'), SHA256)
        S["hmac"] = hasher.hexdigest()

        #S->C Send "OK" if HMAC-SHA256(K, salt) validates
        if S["hmac"] == C["hmac"]:
            print('win')
            break

if __name__ == '__main__':
    main()
