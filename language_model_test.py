#!/usr/bin/env python2.6 

from language_model import *
import unittest
import StringIO


class LanguageModelTest(unittest.TestCase):
    def setUp(self):
        self.language_model = compile(StringIO.StringIO("aaa\naab\nabb\naaa"))
    def test_compile(self):
        expected = {('a', 'a'): {'a': 2, 'b': 1, None: 2}, 
                    ('b', 'b'): {None: 1}, 
                    (None, None): {'a': 4}, 
                    ('a', None): {None: 2}, 
                    ('a', 'b'): {'b': 1, None: 1}, 
                    ('b', None): {None: 2}, 
                    (None, 'a'): {'a': 3, 'b': 1}}

        self.assertEqual(expected, self.language_model)

    def test_entropy(self):
        self.assertAlmostEquals(self.language_model.bits("aaa"), 2.0)
        self.assertAlmostEquals(self.language_model.bits("aab"), 3.32, 2)

    def test_pickling(self):
        self.assertEqual(cPickle.loads(cPickle.dumps(self.language_model)),
                         self.language_model)
    
    def test_construction(self):
        self.assertEqual(LanguageModel(self.language_model),
                         self.language_model)
        
if __name__ == "__main__":
    unittest.main()
    
