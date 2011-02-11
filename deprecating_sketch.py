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
gflags.DEFINE_integer('slots', 2**19, 
"""Must be larger than items * per_item.  Together with per_item this
affects your false_positive rate.  Make this too high and loss of your
bloom-filter can result in password disclosure.  Make this too low and
your users will become frustrated with false positives"""
)

gflags.DEFINE_integer('items', 2**16, 
"""This is the maximum frequency, passwords can have a freq no greater than 1/items""")

gflags.DEFINE_integer('per_item', 2, 'See slots for discussion')

class TooManyHashBitsRequired(Exception):
    def __init__(self, bits):
        exception.__init__(self, "%s bits is just too many for this implementation" % bits )

class DeprecatingSketch(utils.Identity):

    """A probabilistic structure that tracks approximate temporary set membership.

    This data structure will occasionally generate false positives.
    How often a false positive occurs has to do with the "density" of
    bits in the bloom-filter and is a topic beyond the scope of this
    docstring - just accept the parameters the way they are and don't
    fiddle unless you really understand how bloom-filters work.
    
    Items are removed on a round robin basis where "items" is the
    length of the round robin.  Elements added more than "items"
    additions ago will be removed.
    
    This data structure will never generate a false negative.  
    """
    def __init__(self, slots=GFLAGS.slots, items=GFLAGS.items, per_item=GFLAGS.per_item):
        """Create a deprecating sketch
        
        Args:

          slots: The number of bloom-filter slots to create.  Must be
            larger than items * per_item, ideally a small single digit
            factor larger.

          items: The number of items to hold.  When items+1 items are
          added, the first item will be forgotten.  This directly
          specifies how "temporary" the membership is.

          per_item: The number of bits to set per_item.   Deep voodoo here.
        """
          
        self.__slots = [0] * slots 
        self.__que = [None] * items * per_item 
        self.__queoffset = 0 
        self.__per_item = per_item
        self.choose_hash_function()

    def choose_hash_function(self):
        """Assign to self.hashfunc a hashlib function that provides enough bits."""
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
        """Generate hashes for a string.
        
        Args: 
          s: A string to hash

        Returns:
          An array per_item (see constructor) in length with hash values in Z_slots.
        """
        h = int(self.hashfunc(s).hexdigest(), 16)
        for x in range(self.__per_item):
            yield h % len(self.__slots)
            h = h // len(self.__slots)

    def add_hash(self, h):
        """Add to the bloomfilter a hash value.  

        Removes the oldest hash in the roundrobin at the same time."""
        remove = self.__que[self.__queoffset]
        if remove is not None:
            self.__slots[remove] -= 1 
        self.__que[self.__queoffset] = h
        self.__slots[h] += 1 
        self.__queoffset = (self.__queoffset + 1) % len(self.__que) 

    def add(self, s):
        """Add a string to the deprecating_sketch.  

        The oldest string is removed at the same time."""
        map(self.add_hash, self.hashes(s))

    def test_hash(self, h):
        """Test a given hash value for membership.

        Returns 0 if this slot is free, something that evaluates to
        True otherwise.  (it actually returns the number of times this
        bit as been set to true.)
        """
        return self.__slots[h]

    def __getstate__(self):
        return self.__que, self.__queoffset, len(self.__slots), self.__per_item

    def parameters_changed(self):
        """Determine of bloom-filter parameters don't match what is being loaded from disk.  
        
        Return true if the parameters are different and incompatible, return false otherwise.
        """

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
