import binascii
from Crypto.Cipher import AES

def main():
    # open file and read the base64 text
    with open('7.txt', 'rU') as f:
        lines = f.readlines()

    data = ''.join([l.strip() for l in lines])
    iv = bytes(binascii.a2b_base64(data.encode('ascii')))

    key = b"YELLOW SUBMARINE"
    mode = AES.MODE_ECB
    cr = AES.new(key, mode)

    msg = cr.decrypt(iv)
    print (msg)

if __name__ == '__main__':
    main()
