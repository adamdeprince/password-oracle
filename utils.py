#!/usr/bin/env python2.6 


class Identity:
    def __hash__(self):
        hash(self.__identity__())



    def __cmp__(self, other):
        return cmp(self.__identity__(), other.__identity__())

def segment(s, n=3):
    """Segments a string s into substrings of length n

    Args:
      s: string to segment
      n: segment length (defaults to 3)

    Yields:
      Individual segments of s as described below   
    
    Example:
    
    segment("ab") yields:
      [None, None, "a"]
      [None, "a", "b"]
      ["a", "b", None]
      ["b", None]
      """
    padded_string = [None] * (n-1) + list(s) + [None] * (n-1)
    
    for offset in range(len(padded_string) - n + 1):
        yield (tuple(padded_string[offset : offset + n - 1]), padded_string[offset + n - 1])


def all_but_the_last(generator):
    """Yields all but the last item in a sequence.""" 
    second_to_last = generator.next()
    while True:
        last = generator.next()
        yield second_to_last
        second_to_last = last 


def prefixed(s, prefix):
    """Returns the non-prefixed form of s if it starts with prefix.

    Args:
      s: String to examine
      prefix: Prefix to test for

    Returns:
      False is s does not start with prefix, s with the prefix removed otherwise
    """
    return s.startswith(prefix) and s[len(prefix):]
