'''
    21. Implement the MT19937 Mersenne Twister RNG

    You can get the psuedocode for this from Wikipedia. If you're writing
    in Python, Ruby, or (gah) PHP, your language is probably already
    giving you MT19937 as "rand()"; don't use rand(). Write the RNG
    yourself.

'''

class MersenneTwister(object):
    def __init__(self, seed):
        # Create a length 624 array to store the state of the generator
        self.len = 624
        self.MT = [None] * self.len
        self.index = 0
        self.mask = (2**32) - 1
        self.Zerox8 =2**31
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
        
        self.index = (self.index + 1) % 624
        return y
            
    def generate_numbers(self):
        for i in range(self.len):
            y = (self.MT[i] & self.Zerox8) + (self.MT[(i+1) % self.len] & (self.Zerox8 - 1))
            self.MT[i] = self.MT[(i + 397) % self.len] ^ (y >> 1)
            
            if y % 2:
                self.MT[i] ^= 2567483615
            
def main():
    x = MersenneTwister(1)
    mersenne_test_vector = [
        1791095845, 
        4282876139,
        3093770124,
        4005303368,
        491263,
        550290313,
        1298508491,
        4290846341,
        630311759,
        1013994432,
    ]
    
    for i in range(10):
        assert x.extract_num() == mersenne_test_vector[i]

        
if __name__ == '__main__':
    main()