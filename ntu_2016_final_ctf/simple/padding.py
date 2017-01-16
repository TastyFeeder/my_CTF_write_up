import socket
import base64
import sys
PORT = 10128
HOSTNAME = 'csie.ctf.tw'
#input = base64.b64decode('ofJnFC5PuNItJNBhtGWdB3Bwinou6KYSMzsyGmPNaf1W8YLCiX+j13tSzjCoIUg2CtdHdDTcv0EZ/pi7R6rYk2/o8FOUvv6KFLrqDTe9QZU=')
# IV+ciphertext
input = base64.b64decode('OHdoWGJXcWVobkFDZjZ0WqHyZxQuT7jSLSTQYbRlnQdwcIp6LuimEjM7MhpjzWn9VvGCwol/o9d7Us4wqCFINgrXR3Q03L9BGf6Yu0eq2JNv6PBTlL7+ihS66g03vUGV')
#init socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(( HOSTNAME, PORT ))
#list for tmp record plaintext
key=[]
#list for record plaintext
r_key=[]
#recive data until not \n
def recv_data():
    tmp=s.recv(512)
    while tmp == '\n':
        tmp=s.recv(512)
    return tmp
#Implementation of oracle padding for 1 block(16 byte)
def padding(which,tar):
#cut input for insert padding byte
    b1=tar[:16]
    b2=tar[16:32]
#ch is the guess byte of block 2  of tar
    ch = 0
#do until correct padding
    while 1 == 1:
#if ch >= 256 it mean padding fail  maybe input is wrong
        if ch >= 256:
            ch = ch - 1
            print "can't find ch is greater than 256,so record it as 255"
            break
        xor = ''
#padding~~~
        xor = xor + chr(ord(b1[(-1*which)]) ^ which ^ ch)
        for i in range(1,which):
            xor = xor + chr(key[0-i] ^ which ^ ord(b1[0-which+i]))
#make the string for sending
        to_send = base64.b64encode(b1[:(-1)*which]+xor+b2)
#send
        s.send(to_send+'\n')
        tmp=s.recv(512)
#if return true\n -->padding correct and break while
        if tmp == 'true\n':
            break
#else keep padding
        ch = ch + 1
    return ch
#start program
#receive data and print
data=recv_data()
print data
data=recv_data()
print data
#how many block for padding 4
block = 4
#how many byte a block have
block_size = 16
#padding 4 block data
for j in range(0,block):
#every block have 16 byte
    for i in range(0,block_size):
#record correct padding byte
        key.append(padding(i+1,input[j*16:]))
        #print key
        str1 = ''.join(chr(e) for e in key)
        sys.stdout.write('\r'+ str1)
        sys.stdout.flush()
    sys.stdout.write(' ==>reverse==> ')
#record plaintext to r_key
    for i in range(0,16):
        r_key.append(key[15-i])
        sys.stdout.write(chr(key[15-i]))
    print ""
#clear list
    key=[]
#close socket
s.shutdown(socket.SHUT_WR)
print "FLAG is :"
#make list to be str
flag = ''.join(chr(e) for e in r_key)
print flag
