import base64

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
    buffer1 = str("1c0111001f010100061a024b53535009181c")
    buffer2 = str("686974207468652062756c6c277320657965")

    b1 = hex_decode(buffer1)
    xor = xor_list(b1, buffer2)
    xor_string = ''
    for x in xor:
        xor_string += chr(x)

    print xor_string
    print hex_encode(xor_string)
    print xor_string.encode("hex")

if __name__ == '__main__':
    main()
