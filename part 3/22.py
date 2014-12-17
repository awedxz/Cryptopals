'''
    22. "Crack" An MT19937 Seed

    Make sure your MT19937 accepts an integer seed value. Test it (verify
    that you're getting the same sequence of outputs given a seed).

    Write a routine that performs the following operation:

    * Wait a random number of seconds between, I don't know, 40 and 1000.
    * Seeds the RNG with the current Unix timestamp
    * Waits a random number of seconds again.
    * Returns the first 32 bit output of the RNG.

    You get the idea. Go get coffee while it runs. Or just simulate the
    passage of time, although you're missing some of the fun of this
    exercise if you do that.

    From the 32 bit RNG output, discover the seed.

'''
from time import sleep, time
from random import randint

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
                
def test():
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
        

def rand_routine():
    print('sleep 1')
    sleep(randint(40, 1000))
    prng = MersenneTwister(int(time()))
    print('sleep 2; time -', int(time()))
    sleep(randint(40, 1000))
    
    return prng.extract_num()
        
def main():
    test()
    rnd = rand_routine()
    time_now = int(time())
    seed = 0
    
    print('starting guess')
    for i in range(time_now, 0, -1):
        prng = MersenneTwister(i)
        tester = prng.extract_num()
        if tester == rnd:
            seed = i
            break

    print(seed)
   
if __name__ == '__main__':
    main()