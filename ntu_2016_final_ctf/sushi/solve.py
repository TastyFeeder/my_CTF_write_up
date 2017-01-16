from pwn import *
import time
import angr
import base64
HOST = '133.130.124.59'
PORT = 9993
r = remote(HOST,PORT)
time.sleep(0.5)
test = r.recvuntil('base64\n')
print test
data = r.recvuntil('AA==')
print data
de = base64.b64decode(data)
of = open('pp','w')
of.write(de)
of.close()
r.interactive()
