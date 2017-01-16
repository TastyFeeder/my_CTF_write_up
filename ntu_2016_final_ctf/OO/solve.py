from pwn import *
import time
import base64
import angr
HOST = '133.130.124.59'
PORT = 9992
r = remote(HOST,PORT)
time.sleep(0.5)
test = r.recvuntil('base64\n')
print test
data = r.recvuntil('\n\n')
print data
de = base64.b64decode(data)
of = open('qq','w')
of.write(de)
of.close()
stop_target = 0x000000000040333E
p = angr.Project('qq', load_options={'auto_load_libs': False})

pg = p.factory.path_group()
pg.explore(find=stop_target)
found = pg.found[0]
g1_base = 0x603A60 
g2_base = 0x6038C0
g3_base = 0x603AC0
g1 = []
for i in range(10):
    g1.append(int(found.state.se.any_int(found.state.memory.load(g1_base+(i*4), 1))))
print g1
for a in g1:
    r.sendline(str(a))
g2 = []
for i in range(100):
    g2.append(int(found.state.se.any_int(found.state.memory.load(g2_base+(i*4), 1))))
print g2
for a in g2:
    r.sendline(str(a))
g3 = []
#angr get int fail don't know why
for i in range(1000):
    get = found.state.se.any_str(found.state.memory.load(g3_base+(i*4), 4)).encode('hex')
    n_get = ''
    for i in range(4):
        n_get += get[7-(i*2+1)]
        n_get += get[7-(i*2)]
    g3.append(int(n_get,16))
print g3
for a in g3:
    r.sendline(str(a))
r.interactive()
