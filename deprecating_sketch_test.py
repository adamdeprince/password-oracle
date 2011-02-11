#!/usr/bin/env python2.6 

from deprecating_sketch import * 
import unittest
import cPickle

class DeprecatingSketchCrashDummy(DeprecatingSketch):
    def parameters_changed(self):
        return False 

class DeprecatingSketchTest(unittest.TestCase):

    def setUp(self):
        self.sketch = DeprecatingSketchCrashDummy()

    def test_default_hash(self):
        "With default values the DeprecatingSketchCrashDummy should select hashlib.md5"
        self.assertEquals(self.sketch.hashfunc,
                          hashlib.md5)

    def test_empty_hash(self):
        """Empty hashes should not indicate as having anything"""
        self.assertFalse("abc" in self.sketch)

    def test_placed_item_in_hash(self):
        self.sketch.add("abc")
        self.assertTrue("abc" in self.sketch)
        
    def test_pickle(self):
        self.sketch.add("abc")
        pickle_clone = cPickle.loads(cPickle.dumps(self.sketch))
        
        self.assertEquals(self.sketch,
                          pickle_clone)
        
        self.sketch.add("abc")
        self.assertNotEquals(self.sketch, pickle_clone)


class VerySmallDeprecatingSketchCrashDummyTest(unittest.TestCase):
    def setUp(self):
        self.sketch = DeprecatingSketchCrashDummy(slots=1000, items=2, per_item=1)

    def test_sketch_decays(self):
        self.assertFalse("abc" in self.sketch)
        self.sketch.add("abc")
        self.assertTrue("abc" in self.sketch)
        self.sketch.add("def")
        self.assertTrue("abc" in self.sketch)
        self.sketch.add("123")
        self.assertFalse("abc" in self.sketch)


if __name__ == "__main__":
    unittest.main()
    

        
