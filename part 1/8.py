import binascii
from Crypto.Cipher import AES
from collections import Counter

# break a list of byte strings into chunks and looks for duplications at the
# 16 byte chunk level. if there are, it's probably ECB

def detect_ecb(iv_list):
    block_sizes = [16]

    for iv in iv_list:
        for block_size in block_sizes:
            idxs = range(0,len(iv), block_size)
            blocks = []
            for (start,end) in zip(idxs, idxs[1:]):
                blocks.append( iv[start:end] )
                cn = Counter(blocks)
            if cn.most_common()[0][1] > 1:
                return iv
            else:
                pass

    return b''

def main():
    # open file and read the base64 text
    with open('8.txt', 'rU') as f:
        lines = f.readlines()

    iv_list = [bytes.fromhex(line.strip()) for line in lines]

    ecb_item = detect_ecb(iv_list)
    print(ecb_item)

if __name__ == '__main__':
    main()
