#!/usr/bin/python

import sys, os
import random
import string
import time
from Crypto.Cipher import AES
from base64 import b64encode
import secret

KEY = secret.KEY
FLAG = secret.FLAG
IV = ''.join([random.choice(string.letters + string.digits) for i in xrange(16)])
SECRET_STR = secret.secret_string #strings are fixed


def AES_encrypt(m):
    aes = AES.new(KEY, AES.MODE_OFB, IV)
    return b64encode(aes.encrypt(m))

if __name__ == '__main__':
    sys.dont_write_bytecode = True
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
    sys.stdin = os.fdopen(sys.stdin.fileno(), 'r', 0)
    time.sleep(0.5)

    print 'FLAG:', AES_encrypt(FLAG)
 
    print 'Some ciphertexts:'
    for s in SECRET_STR:
        assert(all(c in string.letters + string.digits for c in s))
        print AES_encrypt(s):