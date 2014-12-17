import binascii
import string
import operator
from collections import Counter
import array
import heapq

DEBUG = 0

# fills a key to match the size of text its encrypting against
def fill_key(k, txt):
    p = len(txt)//len(k)
    q = len(txt)%len(k)
    return k*p + k[:q]

# xors a key with some txt
def xor_encrypt(key, txt, pad=True):
    key = fill_key(key, txt) if pad else key
    return bytes([a^b for (a,b) in zip(key, txt)])

# calculates score for letter frequencies
def score_frequency(letter_counts):
    global DEBUG

    score = 0
    total_letters = 0

    otherCount = 0
    puncCount = 0

    ref_punc = [chr(i) for i in range(32, 49)]
    ref_punc += [chr(i) for i in range(58, 65)]
    ref_punc += [chr(i) for i in range(91, 97)]
    ref_punc += [chr(i) for i in range(123, 127)]

    refNum = [chr(i) for i in range(48, 58)]

    refBad = [chr(i) for i in range(0, 32)]
    refBad += [chr(i) for i in range(127, 256)]

    for letter in letter_counts.most_common():
        total_letters += letter[1]

    frequencies = [(char, float(count) / total_letters) for char, count in letter_counts.most_common()]

    for freq in frequencies:
        if freq[0] in string.ascii_letters or freq[0] == ' ':
            score += freq[1] * 2
        elif freq[0] in ref_punc:
            score -= 1 * freq[1]
            puncCount += letter_counts[freq[0]]
        elif freq[0] in refNum or freq[0] in refBad:
            score -= 1 * freq[1]
            otherCount += letter_counts[freq[0]]
        else:
            print('[-] Error in parsing character:', freq[0])

    return score

# calculates the Hamming distance
def hamm_dist(p, q):
  return sum([hamdist_byte(a,b) for (a,b) in zip(p,q)])

# compares two bytes and calculates the number of differences
def hamdist_byte(b1, b2):
  dist = 0
  v = b1^b2
  while v:
    if (v & 1):
      dist += 1
    v = v >> 1
  return dist

# breaks data into chunks / blocks then calculates the hamming dist
# between them, and returns the 3 lowest scoring block sizes
def find_lowest_hamm(data):
    possibles = []
    KEYSIZES = []

    for KEYSIZE in range(2, 41):
        blocks = [data[:KEYSIZE],  data[KEYSIZE:KEYSIZE * 2], data[KEYSIZE*2:KEYSIZE*3],data[KEYSIZE*3:KEYSIZE*4]]
        hamms = []

        for i in range(len(blocks)):
            for j in range(len(blocks)):
                if i == j:
                    pass
                else:
                    hamms.append(hamm_dist(blocks[i], blocks[j])/KEYSIZE)

        avg_hamm = sum(hamms) / len(hamms)
        possibles.append(avg_hamm)

    smallest = heapq.nsmallest(7, possibles)

    for small in smallest:
        KEYSIZES.append(possibles.index(small) + 2)

    print('Trying keysizes of', KEYSIZES)
    print('')
    return KEYSIZES

# creates blocks of size bytes
def get_blocks(data, size=16):
  if len(data)%size != 0:
    padded_len = size*(len(data)//size + 1)
    data = pad(data, padded_len)

  # divide data in size chunks
  num_blocks = len(data)//size

  blocks = []
  for i in range(0, num_blocks):
    st = i*size
    blocks.append(data[st:st+size])

  return blocks

# pads bytes() to make sure they're of equal length
def pad(b, length):
  assert(isinstance(b, bytes))
  assert(len(b) <= length)

  pad_length = length - len(b)
  assert(pad_length < 256) # as we're padding with bytes
  if pad_length:
    padding = bytes((pad_length,))*pad_length
    return b + padding
  else:
    return b

#align a set of blocks of size so that all of the 1 bytes align, 2 bytes align, etc
def align_blocks(blocks, size):
    aligned_blocks = []

    # rearrange the array so that all byte 1's align, etc
    for i in range(0, size):
        aligned_block = bytes()
        for block in blocks:
            aligned_block += block[i].to_bytes(1, 'big')

        aligned_blocks.append(aligned_block)

    return aligned_blocks

def main():
    # possible single character XOR keys
    possible_xor = string.ascii_letters + '  '

    # open file and read the base64 text
    with open('6.txt', 'rU') as f:
        lines = f.readlines()

    data = ''.join([l.strip() for l in lines])
    data = bytes(binascii.a2b_base64(data.encode('ascii')))

    # find lowest hamm dist keysizes
    keysizes = find_lowest_hamm(data)

    # iterate through each of the 3 best keysizes
    for keysize in keysizes:
        print('Trying keysize:', keysize)
        print('----------------------------------------')
        keys = []
        possibles = {}

        # break data into blocks
        blocks = get_blocks(data, keysize)

        # align the blocks
        aligned_blocks = align_blocks(blocks, keysize)

        # iterate through each byte-aligned blocks of data
        for chunk in aligned_blocks:

            # iterate through each possible single key XOR
            for char in possible_xor:

                char = bytes(char, 'ascii')
                xor = xor_encrypt(char, chunk)

                # convert to string for analysis
                xor_decode = xor.decode('ascii')

                # get counts of letters / chars (make everything upper so we don't under count)
                counter = Counter(xor_decode.upper())

                # get score
                counter_score = score_frequency(counter)

                # add score and char to dicts for safe keeping
                possibles[char.decode('ascii')] = counter_score

            # append the best scoring keys to the array
            keys.append(max(possibles.items(), key=operator.itemgetter(1))[0])
            print(sorted(possibles.items(), key=lambda x: -x[1])[:3])

        print('- Best scoring key:', ''.join(keys))
        print('')


if __name__ == '__main__':
    main()
