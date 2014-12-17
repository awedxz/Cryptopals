'''
    23. Clone An MT19937 RNG From Its Output

    Once you have "untemper" working, create a new MT19937 generator, tap
    it for 624 outputs, untemper each of them to recreate the state of the
    generator, and splice that state into a new instance of the MT19937
    generator.

    The new "spliced" generator should predict the values of the original.

    How would you modify MT19937 to make this attack hard? What would
    happen if you subjected each tempered output to a cryptographic hash?

'''

class MersenneTwister(object):
    def __init__(self, seed):
        # Create a length 624 array to store the state of the generator
        self.len = 623
        self.MT = [None] * self.len
        self.index = 0
        self.mask = (2**32) - 1
        self.Zerox8 = 2**31
        self.init_gen(seed)
        
    def init_gen(self, seed):
        self.MT[0] = seed

        # loop over each other element
        for i in range(1, self.len):
            self.MT[i] = (1812433253 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i) & self.mask
                      
    def extract_num(self):
        if (self.index == 0):
            self.generate_numbers()
            
        y = self.MT[self.index]
        
        y ^= y >> 11
        y ^= (y << 7) & 2636928640        
        y ^= (y << 15) & 4022730752
        y ^= y >> 18
        
        self.index = (self.index + 1) % self.len
        return y
            
    def generate_numbers(self):
        for i in range(self.len):
            y = (self.MT[i] & self.Zerox8) + (self.MT[(i+1) % self.len] & (self.Zerox8 - 1))
            self.MT[i] = self.MT[(i + 397) % self.len] ^ (y >> 1)
            
            if y % 2:
                self.MT[i] ^= 2567483615
                       

def reverse_lbitshift_xor(y, n, magic):
    if n == 7: 
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
        y ^= (y << n) & magic
    else:
        y ^= (y << n) & magic
        
    return y
    
def reverse_rbitshift_xor(y, n):
    if y == 18:
        y ^= y >> (n)
    else:
        y ^= y >> (n)
        y ^= y >> (n)
        y ^= y >> (n)
    return y
    
def inverse_temper(y):
    y = reverse_rbitshift_xor(y, 18)
    y = reverse_lbitshift_xor(y, 15, 4022730752)
    y = reverse_lbitshift_xor(y, 7, 2636928640)
    y = reverse_rbitshift_xor(y, 11)

    return y
    
    
def temper(y):
    y ^= y >> 11
    y ^= (y << 7) & 2636928640        
    y ^= (y << 15) & 4022730752
    y ^= y >> 18
    
    return y
    
def main():
    prng = MersenneTwister(1)
    
    MT = []
    idx = 0
    
    for i in range(623):
        MT.append(inverse_temper(prng.extract_num()))
            
    # I could generate the entire MT here but I think this gets the point
    # across so I don't have to duplicate other entire chunks of code!
    prng = MersenneTwister(1)
    for i in range(623):
        assert prng.extract_num() == temper(MT[i])
        
    '''
        How would you modify MT19937 to make this attack hard? 
            - Not sure; randomize the length, perhaps? My math is extremely subpar,
              and my eyes glazed over on the Wiki article, so I'm unsure if the
              length of 624 is significant, but I didn't see anything.
              
        What would happen if you subjected each tempered output to a cryptographic hash?
            - It seems as if you could then use each of these resulting hashes like
              a CTR stream cipher!
    '''

        
if __name__ == '__main__':
    main()