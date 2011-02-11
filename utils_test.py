#!/usr/bin/env python2.6 

import unittest
from utils import * 

class PrefixTest(unittest.TestCase):
    def test_prefixed(self):
        self.assertEquals(prefixed("abc","a"),
                          "bc")

    def test_not_prefixed(self):
        self.assertEquals(prefixed("abc", "b"),
                          False)

class SegmentationTest(unittest.TestCase):
    def test_segment(self):
        expected = [((None, None), "s"),
                    ((None, "s"), "t"),
                    (("s", "t"), "r"),
                    (("t", "r"), "i"),
                    (("r", "i"), "n"),
                    (("i", "n"), "g"),
                    (("n", "g"), None),
                    (("g", None), None)]
        actual = list(segment("string"))
        self.assertEqual(expected, actual)

    def test_segment_with_non_default_length(self):
        expected = [((None,), "s"),
                    (("s",), None)]
        actual = list(segment("s", 2))
        self.assertEqual(expected, actual)

if __name__ == "__main__":
    unittest.main()

