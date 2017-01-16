
from pwn import *
import os
HOST = '140.113.209.24'
PORT = 10003

def mine(w, h, count):
    r.recvline()
    r.recvline()
    print 'W:',w,'H:',h,'count:',count
    matrix = []
    for i in range(w):
        get = r.recvline().split()
        matrix.append(get[1:])
    
    give_in = ""
    for row in matrix:
        for col in row:
            give_in += col
    print give_in

    wf = open('data/in_' + str(w) ,'w')
    wf.write(give_in)
    wf.close()
    os.system('cat '+'data/in_' + str(w) + '|python mines/mines.py mines ' + str(w) + ' ' +str(h) + ' ' + str(count) + '> ' +'data/out_' + str(w))
    rf = open('data/out_' + str(w), 'r')
    out = rf.read()
    out = out.split('\n')[1:-1]#first is space last is total possible arrangements
    print '\n',out 
    for y in range(h):
        for x in range(w):
            if out[y][x] == '1':
                matrix[y][x] = '-1'
            if matrix[y][x] == '-':
                matrix[y][x] = '0'
    print(matrix)

    payload = ""
    for y in range(h):
        for x in range(w):
            payload += matrix[y][x] + " "
    
    r.sendline(payload)

r = remote(HOST, PORT)

for i in range(1,10):
    mine(i * 10, i * 10, i * 100 * i / 5)
r.interactive()

