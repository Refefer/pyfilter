#!/usr/bin/python
import sys
from hashlib import md5, sha1
import math
import optparse

def md5_hash(key):
    return int(md5(key).hexdigest(), 16)

def sha_hash(key):
    return int(sha1(key).hexdigest(), 16)

class BloomFilter(object):
    """
    Simple bloom filter implementation.
    """
    hash_functions = None
    bfilter = None
    def __init__(self, n, p, hash_functions=None):
        """
        
        @param n:  Number of unique items expected
        @type  n:  positive int
        
        @param p:  Probability of false positive
        @type  p:  0 < float(p) < 1
        
        @param hash_functions: Set of hash functions to use
        @type  hash_functions: (h1(), h2(), ...)
        """
        if hash_functions is None:
            hash_functions = (md5_hash, sha_hash, hash)

        self.hash_functions = hash_functions

        # Calculate the size of the bloom filter 
        k = float(len(hash_functions))
        m_bits = math.ceil(1 / (1 - (1 - p ** (1 / k)) ** (1 / (k * n))))
        self.m_bits = m_bits
        self.bfilter = bytearray(int(math.ceil(m_bits / 8)))

    def _hash_key(self, key):
        m_bits = self.m_bits
        for hf in self.hash_functions:
            yield divmod(int(hf(key) % m_bits), 8)

    def insert(self, key):
        """
        Inserts a key into the bloom filter.

        @param key: Key to insert into the bloom filter
        @type  key: "key"

        @return: Whether or not the key was already in the bloomfilter
        @rtype: bool
        """
        contains = True
        for offset, bit in self._hash_key(key):
            mask = 1<<bit
            contains &= bool(self.bfilter[offset] & mask)
            self.bfilter[offset] |= mask
        return contains

def build_parser():
    parser = optparse.OptionParser()

    parser.add_option('-p', '--probability',
                  dest='prob',
                  type="float",
                  default=0.0005,
                  help="Float representing desire false positive rate.  "\
                        "Default is .05%")

    parser.add_option('-n', '--number',
                  dest='number',
                  type="int",
                  default="100000",
                  help="Max number of unique values expected."\
                        "Default is 100,000.")

    return parser

def stream_files(files):
    if files:
        for f in files:
            with file(f) as fin:
                for line in fin:
                    yield line

    else:
        # Stdin
        for line in sys.stdin:
            yield line

if __name__ == '__main__':
    parser = build_parser()
    opts, files = parser.parse_args()
    bf = BloomFilter(opts.number, opts.prob)
    
    # If we have files, use them
    stdout = sys.stdout
    for line in stream_files(files):
        if not bf.insert(line):
            stdout.write(line)
