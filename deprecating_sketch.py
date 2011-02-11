#!/usr/bin/env python2.6 

"""deprecating_sketch.

A deprecating sketch is somewhat like the counting sketch proposed by
Cormac, except it neither allows "credit" for unused passwords nor
bans passwords that were very common before the skethc was put in
place.
"""

import hashlib
import math
import utils 
import gflags
import sys

GFLAGS = gflags.FLAGS 
gflags.DEFINE_integer('slots', 2**19, 'Must be larger than items * per_item.  Together with per_item this affects your false_positive rate.  Make this too high and loss of your bloomfilter can result in password disclosure.  Make this too low and your users will become frustrated with false positives')
gflags.DEFINE_integer('items', 2**16, 'This is the maximum frequency, passwords can have a freq no greater than 1/items')
gflags.DEFINE_integer('per_item', 2, 'See slots for discussion')

class TooManyHashBitsRequired(Exception):
    def __init__(self, bits):
        exception.__init__(self, "%s bits is just too many for this implementation" % bits )

class DeprecatingSketch(utils.Identity):
    def __init__(self, slots=GFLAGS.slots, items=GFLAGS.items, per_item=GFLAGS.per_item):
        self.__slots = [0] * slots 
        self.__que = [None] * items * per_item 
        self.__queoffset = 0 
        self.__per_item = per_item
        self.choose_hash_function()

    def choose_hash_function(self):
        required_bits = math.log(len(self.__slots), 2 ) * self.__per_item
        
        # TODO(deprince): This is a huge potential perforamnce
        # problem.  Bloomfilters don't need cryptographic quality hash
        # functions?  Might FNV, even implemented in Python, be
        # faster?  There is some research that suggests hash bits can
        # reused for a bloom filter, perhaps hash(s) could be used?
        # Honestly however, can it be any worse than
        # HTTPServer.BaseServer?

        if required_bits < 128:
            self.hashfunc = hashlib.md5
        elif required_bits < 160:
            self.hashfunc = hashlib.sha1 
        elif required_bits < 224:
            self.hashfunc = hashlib.sha224
        elif required_bits < 256:
            self.hashfunc = hashlib.sha256
        elif required_bits < 384:
            self.hashfunc = hashlib.sha384
        elif required_bits < 512:
            self.hash_func = hashlib.sha512 
        else:
            raise TooManyHashBitsRequired(required_bits)
            

    def hashes(self, s):
        h = int(self.hashfunc(s).hexdigest(), 16)
        for x in range(self.__per_item):
            yield h % len(self.__slots)
            h = h // len(self.__slots)

    def add_hash(self, h):
        remove = self.__que[self.__queoffset]
        if remove is not None:
            self.__slots[remove] -= 1 
        self.__que[self.__queoffset] = h
        self.__slots[h] += 1 
        self.__queoffset = (self.__queoffset + 1) % len(self.__que) 

    def add(self, s):
        map(self.add_hash, self.hashes(s))

    def test_hash(self, h):
        return self.__slots[h]

    def __getstate__(self):
        return self.__que, self.__queoffset, len(self.__slots), self.__per_item

    def parameters_changed(self):
        return len(self.__que) != GFLAGS.items * GFLAGS.per_item or self.slotlen != GFLAGS.slots or self.__per_item != GFLAGS.per_item

    def __setstate__(self, data):
        self.__que, self.__queoffset, self.slotlen, self.__per_item = data 
        self.__slots = [0] * self.slotlen 
        if self.parameters_changed():
            print >>sys.stderr, "Parameters changed, bloomfilter wiped, password history lost"
            self.__que = [None] * GFLAGS.items * GFLAGS.per_item 
        else:
            for offset in self.__que:
                if offset:
                    self.__slots[offset] += 1
        self.choose_hash_function()

    def __identity__(self):
        return self.__slots, self.__que, self.__queoffset 
            
    def __contains__(self, s):
        return sum(map(self.test_hash, self.hashes(s))) != 0
