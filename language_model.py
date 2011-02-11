#!/usr/bin/env python2.6 

"""language_model

Utility methods to process the raw password data file from the Rockyou password breach.

When run as a program acts as a languge model compiler.

# ./language_model < UserAccount-passwords.txt > language_model.pickle
"""


import cPickle
import math
import utils 


class Histogram(dict):
    """A histogram that returns the bits entropy of an element."""

    def __init__(self, data={}):
        dict.__init__(self, data)
        self.__counter = sum(data.values())

    def bits(self, key, default=None):
        """Return the number of bits entropy for a given value.
        
        Args:
          key: Key value to return the entropy for
          default: Default value to return if key is not present. 
        
        Returns:
          floating point value indicating the number of "bits" entropy key represents, or if absennt, default

        Cavets:
          This is a dict subclass that overrides a dict.   
        """
        if key not in self:
            return default 
        
        return math.log(self.__counter / self[key], 2)

    def increment(self, key, count=1):
        """Increment number of times key occurs by count (defaults to 1)"""
        self[key] = self.get(key, 0) + count 
        self.__counter += count

    def __setstate__(self, data):
        self.update(data)
        self.__counter = sum(self.values())

    def __getstate__(self):
        return dict(self)


class DummyHistogram:
    """A "histogram" to fill in for missing values."""
    def bits(self, key, default):
        "Dummy histograms contain no data - returns default"
        return default
        
class LanguageModel(dict):
    """A n-tuple language model container."""
    def __init__(self, data={}, default_bits=6.5):
        """Create a new LanguageModel

        Args:
          default_bits: (default 6.5) A float indicaiting the number
          of bits to assign if presented with a tuple not in the
          model.
        """
        dict.__init__(self, data)
            
        self.__default_bits = default_bits 

        self.__dummy_histogram  = DummyHistogram()

        for key, value in self.items():
            self[key] = Histogram(value)

    def extend(self, tuples):
        """Extend this lanugage mode with a series of n-tuples from utils.segment."""
        for context, value in tuples:
            if context not in self:
                self[context] = Histogram()
            self[context].increment(value)            

    def get(self, key):
        if key not in self:
            return self.__dummy_histogram
        return dict.get(self, key)

    def bits(self, s):
        """Compute the bits of entropy in a string.

        If the string uses characters missing from the language model,
        __init__(default_bits) will be used for that element instead.

        Args:
          s: String to compute the entropy for
        """
        total_bits = 0
        for context, value in utils.all_but_the_last(utils.segment(s)):
            total_bits += self.get(context).bits(value, self.__default_bits)
        return total_bits 

    def __getstate__(self):
        """Saves this language model to a string.

        """
        return dict(self), self.__default_bits

    def __setstate__(self, data):
        data, self.__default_bits = data
        self.__dummy_histogram  = DummyHistogram()
        print len(self)
        self.update(data)

def compile(f, n=3):
    """Compile the raw password database.

    Builds a histogram of n tuples provided by f.

    Args:
      f: File containing raw password data
      n: tuple length (defaults to 3)

    Returns:
      LanguageModel
    """
    language_model = LanguageModel()

    for line in list(f):
        language_model.extend(utils.segment(line.strip(), n))
    return language_model
            

if __name__ == "__main__":
    import sys
    cPickle.dump(compile(sys.stdin), sys.stdout)

