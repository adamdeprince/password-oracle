#!/usr/bin/env python2.6 

"""password_oracle

A password quality oracle implemented as a HTTP server.  Given a
password it will answer whether the password has been used recently
and how "common" the password is compared to a list of common words.

For documentation of command line parameters:

./pasword_oracle.py --help 

Tutorial:

1. Compile a word list as follows.  A short list that is quick to
compile and download is provided, but if you are patient I recommend
you download and use the Rockyou password corpus.  Also if your list
is long be patient, on a "typical" machine (MacBook Air 1.86ghz) the
compiler will process about 1/2 million lines per minute Also note
that repeated words increase the weight of that word.

# grep -v '#' password.lst |  ./language_model.py | gzip -9 > language_model.pickle.gz 

2. Start your server.  Note that changing bloom-filter parameters will
erase your recent password history.  The server will by default store
its history data in "bloom_filter.pickle", but by default no language model is loaded.

BTW, by default the bloom-filter tables are setup for a 65,536 element
history.  This means that no password can occur more than 1 out of
ever 65,536 times.  --items indicates how many items are actually
stored at once, while I change it for the demo, changing it without
changing the other parameters will lead to security problems -- with
only three items and the other settings as they are it is actually
possible to figure out what those three passwords are (slots should
be a small single digit multiple of items * per_item, and per_items
should be a small single digit number.)  But we change items to make
the demo easier.


# ./password_oracle.py --language_model=language_model.pickle  --items=3

Now in another window lets ask the oracle if 123456 has recently been
used as a password:

# curl --get -d password=123456 127.0.0.1:8000/available.json
true 

It is available, so it hasn't been used recently.  Lets ask what the
oracle thinks about the quality of the password (this demo assumes you
loaded the RockYou password list, not the silly demo provided in
passwords.lst.)

# curl --get -d password=123456 127.0.0.1:8000/entropy.json
6.9068905956085187

6.9 bits of entropy.  Not to good.  Hey, try this, ask about 12345

# curl --get -d password=12345 127.0.0.1:8000/entropy.json; echo 
8.2288186904958813

Neat, huh?  123456 is so common, so much more common than passwords
than end in 45 that adding that extra 6 actually reduces the entropy
of your password.  Longer passwords are not automatically better than
shorter passwords.  Lets get off this tangent write to the
bloom-filter.

Because 123456 is available, I've decided to use it:

# curl  -d password=123456 127.0.0.1:8000/add

There is nothing here preventing two people from requesting the same
password at the same time.  See the README file for a discussion of
why this isn't a problem.

Now lets see if this password is available.e

# curl --get -d password=123456 127.0.0.1:8000/available.json
false

One of the features of a deprecating sketch is it throttles the use of
passwords, it isn't a forever ban.  Because --items=3, "123456" will
be forgotten after three more passwords.

# curl  -d password=1234 127.0.0.1:8000/add
# curl --get -d password=123456 127.0.0.1:8000/available.json
false
# curl  -d password=12345 127.0.0.1:8000/add
# curl --get -d password=123456 127.0.0.1:8000/available.json
false
# curl  -d password=12345 127.0.0.1:8000/add
# curl --get -d password=123456 127.0.0.1:8000/available.json
true


Caveats

  Changing the deprecating sketch's thresholds will zero out its
  underlying bloom filter.

  We're passing passwords in the clear with this API.  I hope this
  server isn't facing the public Internet and talking to a java script
  client in the user's browser.

  When adding passwords this program doesn't care if you are adding
  the same or different passwords; old entries are flushed after
  however many adds are specified in --items.

"""

import BaseHTTPServer
import cPickle
import cgi
import deprecating_sketch
import gflags 
import gzip
import json
import language_model
import signal 
import sys 
import urlparse 
import utils

from language_model import LanguageModel, Histogram

GFLAGS = gflags.FLAGS 

gflags.DEFINE_string('path', '/', 'URL prefix.')
gflags.DEFINE_string('host', '', 'Host addr to listen to')
gflags.DEFINE_integer('port', 8000, 'Port addr to listen to')
gflags.DEFINE_string('language_model', None, 'Language model to load')
gflags.DEFINE_string('bloom_filter', 'bloom_filter.pickle', 'Bloomfilter to load')


HTTP_UNAVAILABLE = 503
HTTP_OK = 200 
HTTP_CREATED = 201 
HTTP_NOT_FOUND = 404
HTTP_BAD_FORMAT = 415 

ERR_INTERRUPTED = 4 


class PasswordOracleRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def path_prefix(self):
        return GFLAGS.path

    def get_command(self):
        scheme, netloc, path,  params, query, fragment = urlparse.urlparse(self.path)
        if utils.prefixed(path, self.path_prefix()):
            return path[len(self.path_prefix()):]

    def get_password(self):
        import StringIO
        scheme, netloc, path,  params, query, fragment = urlparse.urlparse(self.path)
        data = cgi.parse_qs(query)
        password = data.get('password')
        if password:
            return password[0]

    def compute_entropy(self, password):
        if self.server.language_model:
            return self.server.language_model.bits(password)

    def compute_available(self, password):
        return password not in self.server.sketch

    def do_GET(self):
        password = self.get_password()
        if not password:
            self.send_response(HTTP_NOT_FOUND, 'No password provided')
            return 

        function, format = self.get_command().split('.',2)

        function = {'entropy':self.compute_entropy,
                    'available':self.compute_available,
                    'all':lambda x:dict(entropy=self.compute_entropy(x), 
                                     available=self.compute_available(x))}.get(function)

        format = {'json': json.dumps}.get(format)
        
        if not function:
            return self.send_response(HTTP_NOT_FOUND, 'Unknown function')
        if not format:
            return self.send_response(HTTP_BAD_FORMAT, 'Unknown format')
        
        data = function(password)
        if data is None:
            return self.send_response(HTTP_UNAVAILABLE)
        self.send_response(HTTP_OK)
        self.end_headers()
        
        self.wfile.write(format(data))

    def get_post_password(self):
        form = cgi.FieldStorage(
            fp=self.rfile, 
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        return form['password'].value
        

    def do_POST(self):
        if self.get_command() != 'add':
            return self.send_response(HTTP_NOT_FOUND, 'Unknown command')
        
        password = self.get_post_password()
        if not password:
            return self.send_response(HTTP_NOT_FOUND, 'Missing password')
        
        self.send_response(HTTP_CREATED)
        self.end_headers()
        self.server.sketch.add(password)


class PasswordOracleServer(BaseHTTPServer.HTTPServer):

    @staticmethod 
    def load(pathname, default_class, open=open):
        if pathname:
            try:
                return cPickle.load(open(pathname))
            except Exception, ex:
                pass
        return default_class()

    @classmethod
    def sketch_factory(cls, sketch_path):
        return cls.load(sketch_path, deprecating_sketch.DeprecatingSketch)
    
    @classmethod
    def language_model_factory(cls, language_model_path):
        return cls.load(language_model_path, language_model.LanguageModel, open=gzip.open)

    def save(self, *_):
        cPickle.dump(self.sketch, open(self.sketch_path, "w+"))

    def __init__(self, language_model_path, sketch_path, *args, **kwargs):
        BaseHTTPServer.HTTPServer.__init__(self, *args, **kwargs)
        self.sketch = self.sketch_factory(sketch_path)
        self.language_model = self.language_model_factory(language_model_path)

        self.sketch_path = sketch_path

    def run_forever(self):
        import select 
        signal.signal(signal.SIGTERM, self.save)
        try:
            while True:
                try:
                    self.handle_request()
                except select.error, err:
                    # Side effect of signal catching ... 
                    if (err[0], err[1]) != (ERR_INTERRUPTED, 'Interrupted system call'):
                        raise err
        except KeyboardInterrupt:
            self.save()


def main(argv):
    try:
        argv = GFLAGS(argv)  # parse flags
    except gflags.FlagsError, e:
        print '%s\nUsage: %s ARGS\n%s' % (e, sys.argv[0], GFLAGS)
        sys.exit(1)
    server_address = (GFLAGS.host, GFLAGS.port)
    PasswordOracleServer(GFLAGS.language_model, 
                         GFLAGS.bloom_filter, 
                         server_address, 
                         PasswordOracleRequestHandler).run_forever()


if __name__ == "__main__":
    main(sys.argv)
