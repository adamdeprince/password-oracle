#!/usr/bin/env python2.6 

import unittest
import deprecating_sketch
import language_model 
import StringIO
from password_oracle import * 

PREFIX = "/prefix/"

class FakeServer:
    def __init__(self, sketch, language_model):
        self.sketch = sketch
        self.language_model = language_model 
        

class PasswordOracleRequestHandlerCrashDummy(PasswordOracleRequestHandler):
    def __init__(self, sketch, language_model):
        self.server = FakeServer(sketch, language_model) 
        self.headers_ended = False 
        self.wfile = StringIO.StringIO()

    def path_prefix(self):
        return PREFIX 

    def send_response(self, *value):
        self.response_code = value 

    def end_headers(self):
        self.headers_ended = True 

    def get_post_password(self):
        # Not bothering to test cgi.FieldStorage.  Pretty sure it works. 
        return self.test_password


class PasswordOracleRequestHandlerTest(unittest.TestCase):
    def setUp(self):
        self.handler = PasswordOracleRequestHandlerCrashDummy(
            deprecating_sketch.DeprecatingSketch(slots=1000, items=2, per_item=1),
            language_model.compile(StringIO.StringIO("aaa\naab\nabb\naaa")))

    def test_get_fails_on_bad_prefix(self):
        self.handler.path = '/abc/'
        self.handler.do_GET()
        self.assertEquals(self.handler.response_code[0], 404)
    
    def test_post_fails_on_bad_prefix(self):
        self.handler.path = '/abc/'
        self.handler.test_password='secret'
        self.handler.do_POST()
        self.assertEquals(self.handler.response_code[0], 404)

    def test_has_entropy(self):
        self.handler.path = PREFIX + "entropy.json?password=aaa"
        self.handler.do_GET()
        self.assertEquals(self.handler.response_code[0], 200)
        self.assertAlmostEqual(json.loads(self.handler.wfile.getvalue()), 2.0)

    def test_missing_entropy_skipped(self):

        self.handler.path = PREFIX + "entropy.json?password=aaa"
        self.handler.data = dict(password="aaa")
        self.handler.server.language_model.clear()
        self.handler.do_GET()
        self.assertEquals(self.handler.response_code[0], 503)

    def test_get_all(self):
        self.handler.path = PREFIX + "all.json?password=aaa"
        self.handler.do_GET()
        actual = json.loads(self.handler.wfile.getvalue())
        self.assertAlmostEqual(actual['entropy'], 2.00)
        self.assertEqual(actual['available'], True)
        

class PasswordOracleRequestHandlerComplexTest(unittest.TestCase):
    def test_post_writes_to_sketch(self):
        sketch = deprecating_sketch.DeprecatingSketch(slots=100, items=2, per_item=1)

        handler = PasswordOracleRequestHandlerCrashDummy(
            sketch, 
            language_model.compile(StringIO.StringIO("aaa\naab\nabb\naaa")))

        handler.path = PREFIX + "available.json?password=secret"
        handler.data = dict(password="secret")
        handler.do_GET()
        self.assertEquals(handler.response_code[0], 200)
        self.assertTrue(json.loads(handler.wfile.getvalue()))

        handler = PasswordOracleRequestHandlerCrashDummy(
            sketch, 
            language_model.compile(StringIO.StringIO("aaa\naab\nabb\naaa")))

        handler.path = PREFIX + "add"
        handler.test_password='secret'
        handler.do_POST()
        self.assertEquals(handler.response_code[0], 201)

        handler = PasswordOracleRequestHandlerCrashDummy(
            sketch, 
            language_model.compile(StringIO.StringIO("aaa\naab\nabb\naaa")))

        handler.path = PREFIX + "available.json?password=secret"
        handler.do_GET()
        self.assertFalse(json.loads(handler.wfile.getvalue()))

        

if __name__ == "__main__":
    unittest.main()
