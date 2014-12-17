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
    xordList = []
    for a in buffer1:
        xordList.append(a ^ buffer2[counter])
        counter += 1

    return xordList


def score_frequency(letterCounts):
    score = 0
    badscore = 0
    totalLetters = 0

    letterCount = 0
    otherCount = 0
    puncCount = 0

    variances = []
    refLetterFreq = {'E': .1270, 'T': .906, 'A': .817, 'O': .751, 'I': .697, 'N': .675, 'S': .633, 'H': .609, 'R': .599, 'D': .425, 'L': .403, 'C': .278, 'U': .276, 'M': .241, 'W': .236, 'F': .223, 'G': .202, 'Y': .197, 'P': .193, 'B': .129, 'V': .098, 'K': .077, 'J': .015, 'X': .015, 'Q': .010, 'Z': .007}

    refPunc = [chr(i) for i in range(33, 49)]
    refPunc += [chr(i) for i in range(58, 65)]
    refPunc += [chr(i) for i in range(91, 97)]
    refPunc += [chr(i) for i in range(123, 127)]

    refNum = [chr(i) for i in range(48, 58)]

    refBad = [chr(i) for i in range(0, 32)]
    refBad += [chr(i) for i in range(127, 256)]

    for letter in letterCounts.most_common():
        if letter[0] in string.letters:
            totalLetters += letter[1]

    frequencies = [(char, float(count) / totalLetters) for char, count in letterCounts.most_common()]

    for freq in frequencies:
        if freq[0] in refLetterFreq:
            variances.append(abs(freq[1] - refLetterFreq[freq[0]]))
            letterCount += 1*letterCounts[freq[0]]
        elif freq[0] == ' ':
            pass
        elif freq[0] in refPunc:
            variances.append(100)
            puncCount += 1*letterCounts[freq[0]]
        elif freq[0] in refNum:
            variances.append(100)
            otherCount += 1*letterCounts[freq[0]]
        elif freq[0] in refBad:
            variances.append(100)
            otherCount += 1*letterCounts[freq[0]]
        else:
            print '[-] Error in parsing character:', freq[0]

    badscore = sum(variances) / float(len(variances))

    return -badscore

def main():
    possible_keys = string.printable
    possible_messages = {}
    possible_xors = [line.strip() for line in open('xors.txt')]

    for xor in possible_xors:
        encoded_hex = xor

        decoded_hex = hex_decode(encoded_hex)

        for a in possible_keys:
            buffer2 = [ord(a) for i in range(len(decodedHex))]
            xor = xor_list(decoded_hex, buffer2)
            xor_string = ''
            for x in xor:
                xor_string += chr(x)

            if(all(x in possible_keys for x in xor_string)):
                counter = collections.Counter(xor_string.upper())
                counter_score = score_frequency(counter)
                possible_messages[xor_string] = counterScore

    decoded = max(possible_messages.iteritems(), key=operator.itemgetter(1))[0]
    t = sorted(possible_messages.iteritems(), key=lambda x:-x[1])[:3]
    print t
    print hex_encode(decoded) #original hex string

if __name__ == '__main__':
    main()
