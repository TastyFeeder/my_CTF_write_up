from pwn import *
import time
import angr
import base64
HOST = '133.130.124.59'
PORT = 9991

r = remote(HOST,PORT)
time.sleep(0.5)
test = r.recvuntil('base64\n')
for y in range(3):
    print test
    data = r.recvuntil('==')
    print data
    de = base64.b64decode(data)
    of = open('qq','w')
    of.write(de)
    of.close()

    target_address = 0x0000000000400AF5 #put addree here 
    p = angr.Project('qq', load_options={'auto_load_libs': False})

    pg = p.factory.path_group()
    pg.explore(find=target_address)
    ans = pg.found[0].state.posix.dumps(0).split('\n')[:-1]
    print ans
    for x in ans:
        r.sendline(x)
        r.recvuntil('Piece')
    if y !=2:
        r.recvuntil('GJ!\n')
r.interactive()
