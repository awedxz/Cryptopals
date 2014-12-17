import base64

def hex_decode(hex_string):
    decoded_string = ''
    for a in zip(hex_string[0::2], hex_string[1::2]): # iterate over 2 elements at a time (hex)
        b = ''.join(a)                                                    # combine each element into one hex pair
        c = int(b, 16)                                                   # convert hex to ascii
        d = chr(c)
        decoded_string += d

    return decoded_string

def main():
    one_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

    # easy way
    ans_one = one_hex.decode("hex")
    ans_one = base64.b64encode(ans_one)

    print ans_one

    # manual way
    ans_two = hex_decode(one_hex)
    ans_two = base64.b64encode(ans_two)
    print ans_two

if __name__ == '__main__':
    main()
