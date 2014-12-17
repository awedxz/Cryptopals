import base64
import struct
import string
from Crypto.Cipher import AES
from random import randint
from collections import Counter

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

def main():
   tst_padding1 = "ICE ICE BABY\x04\x04\x04\x04"
   tst_padding2 = "ICE ICE BABY\x05\x05\x05\x05"

   print(validiate_pks7(tst_padding1))
   validiate_pks7(tst_padding2)

if __name__ == '__main__':
    main()
