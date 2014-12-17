from Crypto.Cipher import AES
from math import floor
from base64 import b64decode
from struct import pack
from random import randint

b64s = [
   'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
   'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
   'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
   'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
   'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
   'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
   'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
   'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
   'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
   'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
   'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
   'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
   'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
   'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
   'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
   'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
   'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
   'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
   'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
   'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
   'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
   'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
   'U2hlIHJvZGUgdG8gaGFycmllcnM/',
   'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
   'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
   'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
   'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
   'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
   'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
   'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
   'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
   'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
   'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
   'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
   'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
   'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
   'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
   'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
   'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
   'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
]


class CTRCounter(object):
    def __init__(self, bits=64, init=0, nonce=b'', little_endian = True):
        self.bits = bits
        self.count = init - 1
        self.nonce = nonce
        self.little_endian = little_endian

    def __call__(self):
        self.count += 1
        num_bytes = int((self.count.bit_length()) / 8)
        num_bytes = 1 if (num_bytes < 1) else num_bytes
        other_bytes = b'\x00' * floor(((self.bits / 8) - num_bytes))
        if self.little_endian:
            return self.nonce + (self.count).to_bytes(num_bytes, byteorder='little') + other_bytes
        else:
            return self.nonce + other_bytes + (self.count).to_bytes(num_bytes, byteorder='big')


def gen_AES_key(length=16):
    key = bytes()
    for i in range(length):
        key += pack('B', randint(0,255))

    return key


def score_frequency(letter_list):
    # http://mdickens.me/typing/letter_frequency.html

    returned_letters = []
    letters_by_rank = ' eainsrhdcumolfgpywb,.vtk-"\'xjqz)(:!?;/[]|*=_+>\<&`~{}'

    for letters in letter_list:
       ranks = []

       for letterint in letters:
           letter = chr(letterint).lower()
           ranks.append(letters_by_rank.index(letter))

       return_index = ranks.index(min(ranks))

       returned_letters.append(chr(letters[return_index]))

    return returned_letters


def ctr_encrypt(data, key, ctr, nonce = None):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    blocks = get_blocks(data)

    encry = bytes()

    for block in blocks:
        number = ctr()
        enc = cr.encrypt(number)
        ct = xor_encrypt(enc, block)
        encry += ct

    return encry


def ctr_decrypt(data, key, ctr, nonce = None):
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    blocks = get_blocks(data)

    decry = bytes()

    for block in blocks:
        number = ctr()
        enc = cr.encrypt(number)
        pt = xor_encrypt(enc, block)
        decry += pt

    return decry


def get_blocks(data, size=16):
    num_blocks = len(data)//size + 1

    blocks = []
    for i in range(0, num_blocks):
        st = i*size
        blocks.append(data[st:st+size])

    return blocks

# xors bytes against a key
def xor_encrypt(block, key):
    return bytes([a^b for (a,b) in zip(key, block)])

'''
    Instructions on this one weren't super clear like other ones,
    so I just went at this at the most basic (dumb) way I could think:
    Brute force + trial / error + manually looking at results and tweaking
    from there.

'''

def main():
    nonce = b'\x00' * 8
    key = gen_AES_key()
    max_size = 0
    encrypted = []

    for line in b64s:
        ctr = CTRCounter(bits = 64, init = 0, nonce=nonce, little_endian = True)
        b64 = b64decode(line)
        enc = ctr_encrypt(b64, key, ctr)
        max_size = len(enc) if len(enc) > max_size else max_size
        encrypted.append(enc)

    letters = b' etaoinsrhldcumfgpywb,.vkABCDEFGHIJKLMNOPQRSTUVWXYZ\'"-xjqz)(:!?;/[]|*=_+>\<&`~{}'
    letters = list(letters)

    # get list of possible keystream bytes for each position
    # in first block via brute force
    letters_by_place = []

    for i in range(16):
        letters_by_place.append([])

        for letter in letters:
            found = True

            ksg = letter ^ encrypted[0][i]

            for cipher in encrypted[1:]:
                ptg = cipher[i] ^ ksg
                if not (
                        (ptg >= 97 and ptg <= 122) or
                        (ptg >= 63 and ptg <= 90) or
                        ptg == 32 or
                        ptg == 33 or
                        ptg == 34 or
                        ptg == 44 or
                        ptg == 45 or
                        ptg == 46 or
                        ptg == 58 or
                        ptg == 59
                    ):
                    found = False
                    break

            if found:
                letters_by_place[i].append(letter)

    # if we somehow didn't pick something up, try everything
    for i in range(len(letters_by_place)):
        if len(letters_by_place[i]) == 0:
            letters_by_place[i] = letters

    # capitalize first words
    scored_letters = score_frequency(letters_by_place)
    scored_letters[0] = scored_letters[0].upper()

    scored_letters = bytes(''.join(scored_letters), 'ascii')
    keystream = xor_encrypt(scored_letters, encrypted[0])

    pts = []
    
    # break all of the first blocks using the keystream
    for cipher in encrypted:
        pt = xor_encrypt(cipher[:16], keystream)
        pts.append(pt)

    print(pts) #....leads me to Easter, 1916 by Yeats, where I can decipher the rest


if __name__ == '__main__':
    main()
