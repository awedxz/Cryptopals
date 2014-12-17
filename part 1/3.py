import base64
import string
import collections
import operator

def hex_decode(hex_string):
    decoded= []
    for a in zip(hex_string[0::2], hex_string[1::2]):
        b = ''.join(a)
        c = int(b, 16)
        decoded.append(c)

    return decoded


def hex_encode(string):
    hex_string = ''
    for a in string:
        b = ord(a)
        c = hex(b)
        d = c[2:]
        hex_string += d

    return hex_string


def xor_list(buffer1, buffer2):
    counter = 0
    xord_list = []
    for a in buffer1:
        xord_list.append(a ^ buffer2[counter])
        counter += 1

    return xord_list

""" score_frequency
    Calculates a score for a counter object of letters

    Calculates this score using rough letter frequencies

    - Returns the int score of the letter_counts
"""
def score_frequency(letter_counts):
    score = 0
    letters_in_order = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    bad_letters= "\\n!@#$%^&*()_+=-;\'/.,:\"\?\<"

    # in case i need to fine tune the letter scoring some day
    # refLetterFreq = {'E': .1270, 'T': .906, 'A': .817, 'O': .751, 'I': .697, 'N': .675, 'S': .633, 'H': .609, 'R': .599, 'D': .425, 'L': .403, 'C': .278, 'U': .276, 'M': .241, 'W': .236, 'F': .223, 'G': .202, 'Y': .197, 'P': .193, 'B': .129, 'V': .098, 'K': .077, 'J': .015, 'X': .015, 'Q': .010, 'Z': .007}

    total_letters =  sum(letter_counts.values())
    frequencies = [(char, float(count) / total_letters) for char, count in letter_counts.most_common()]

    for i in frequencies[:6]:
        if i[0].upper() in letters_in_order[:6]:
                score += 2
    for j in frequencies[-6:]:
        if j[0].upper() in letters_in_order[-6:]:
                score += .5
    for k in frequencies:
        if k[0] in bad_letters:
                score -= .5

    return score

def main():
    encoded_hex = str("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    possible_keys = string.printable

    decoded_hex = hex_decode(encoded_hex)
    possible_messages = {}

    for a in possible_keys:
        buffer2 = [ord(a) for i in range(len(decodedHex))]
        xor = xor_list(decoded_hex, buffer2)
        xor_string = ''
        for x in xor:
            xor_string += chr(x)

        if(all(x in possible_keys for x in xor_string)):
            counter = collections.Counter(xor_string)
            counter_score = score_frequency(counter)
            possible_messages[xor_string] = counter_score

    print max(possible_messages.iteritems(), key=operator.itemgetter(1))[0]


if __name__ == '__main__':
    main()
