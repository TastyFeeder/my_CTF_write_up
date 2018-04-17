import string
import urllib
import requests
import random
import hashlib
##xxd -l 320 2.pdf|xxd -r >2.data
if __name__ == "__main__":
    HOST = "https://quiz.ais3.org:32670/"
#    fo1 = open('1.data','rb').read()
#    fo2 = open('2.data','rb').read()
    fo1 = open('1.pdf','rb').read()[:320]
    fo2 = open('2.pdf','rb').read()[:320]
    S = 'Snoopy_do_not_like_cats_hahahahaddaa_is_PHD1'
    
    while(True):
        S_test = S
        for i in range(16):
            S_test += random.choice(string.letters)
        m = hashlib.sha1()
        m.update(fo1+S_test)
        shone = m.digest().encode('hex')
        print 'Now trying:',shone
        if shone.startswith('f00d'):
            S = S_test
            break
    post_data = {'username':fo1+S,'password':fo2+S}
#    req = requests.post(HOST,data=post_data)
#    print req.content
    fo1 = open('my1.data','wb').write(post_data['username'])
    fo2 = open('my2.data','wb').write(post_data['password'])
