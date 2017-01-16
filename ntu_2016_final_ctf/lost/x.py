ALPHA = string.printable
def keygen(key, placeholder='\x00'):
    assert placeholder in key
    q = [array.array('c', key)]
    while q:
        key, q = q[0], q[1:]
        idx = key.index(placeholder)
        if key.count(placeholder) == 1:
            for i in ALPHA:
                key[idx] = i
                yield key[:]
        else:
            for i in ALPHA:
                key[idx] = i
                q.insert(0, key[:])
def eq(expected, guessed):
    for e, g in zip(expected, guessed):
        if e != '\0':
            if g != e:
                return False
    return True

def AES_CBCd(key, msg, iv):
# print('DEC(k=%s, msg=%s, iv=%s)' % (str(key), repr(msg), iv))
    obj = AES.new(key, AES.MODE_CBC, iv)
    return obj.decrypt(msg)
def parse_pcap(pcap):
    KEY = np.zeros(16, np.byte)
    PLAIN = np.zeros(32, np.byte)
    AES_KEY_PLAIN = np.zeros(64, np.byte) # hex-encoded
    AES_KEY_FLAG = np.zeros(64, np.byte)
# hex-encoded
    tup = (KEY, PLAIN, AES_KEY_PLAIN, AES_KEY_FLAG)
    for packet in rdpcap(pcap):
# 0x8 is PSH flag
        if not packet[TCP].getfieldval('flags') & 0x8:
            continue
        for store, line in zip(tup, packet.load.splitlines()[:4]):
            store |= np.frombuffer(line.split(' = ', 1)[-1].replace('*', '\0'), np.byte)
    print repr(KEY.tostring())
    print repr(PLAIN.tostring())
    print repr(AES_KEY_PLAIN.tostring())
    print repr(AES_KEY_FLAG.tostring())
    return map(lambda t: t.tobytes(), tup)

def solve(KEY, PLAIN, AES_KEY_PLAIN, AES_KEY_FLAG):
    sPLAIN = do_slice(PLAIN, len(KEY))
    sPLAIN_ENC = do_slice(AES_KEY_PLAIN, len(KEY) * 2)
    assert len(sPLAIN) == len(sPLAIN_ENC)
    for k in keygen(KEY):
        for i, (pn, cn) in reversed(tuple(enumerate(zip(sPLAIN[1:], sPLAIN_ENC[1:]), 1))
            cn = binascii.unhexlify(cn)# C_n
            cn_1 = AES_CBCd(k, cn, pn)# C_{n-1}
            cn_1_hex = binascii.hexlify(cn_1)
            if eq(sPLAIN_ENC[i - 1], cn_1_hex):
                sPLAIN_ENC[i - 1] = cn_1_hex
            else:
                break
    else:
            iv = AES_CBCd(k, cn_1, sPLAIN[0])
    return AES_CBCd(k, binascii.unhexlify(AES_KEY_FLAG), iv)

