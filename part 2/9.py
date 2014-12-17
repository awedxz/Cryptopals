# pads bytes() to make sure they're of equal length
def pad(block, length):
  pad_length = length - len(block)
  padding = b'\x04'

  if pad_length:
    return block + (padding*pad_length)
  else:
    return block

def main():
    block = 'YELLOW SUBMARINE'
    length = 20

    padded_block = pad(block, length)

    print(padded_block)
    print(len(padded_block))


if __name__ == '__main__':
    main()
