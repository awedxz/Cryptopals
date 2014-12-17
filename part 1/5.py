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

def main():
    string_to_encode = str("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
    key = "ICE"

    with open ("xors2.txt", "r") as myfile:
        string_to_encode=myfile.read()
    key = "HIIIHI"

    string_to_encode = base64.b64decode(string_to_encode)

    # Convert strings into lists of ascii ints (convenient since code is already written)
    ordlist = hex_decode(string_to_encode.encode("hex"))
    ordxor = hex_decode(key.encode("hex"))

    # Fill buffer so it's the same size as the string_to_encode for repeating XOR
    buffer2 = []
    counter = 0
    for i in range(len(ordlist)):
        buffer2.append(ordxor[counter])
        counter += 1
        if counter == len(ordxor):
            counter = 0

    xor = xor_list(ordlist, buffer2)
    xor_string = ''
    for x in xor:
        xor_string += chr(x)

    print xor_string
    print hex_encode(xor_string)

if __name__ == '__main__':
    main()
