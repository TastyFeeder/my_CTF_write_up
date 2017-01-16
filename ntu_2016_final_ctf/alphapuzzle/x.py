import base64

f = open('in','r')
data = f.read()
print data
de = base64.b64decode(data)
of = open('qq','w')
of.write(de)
f.close()
of.close()
