from pwn import *
if __name__ == "__main__":
    array = [964600246,1376627084,1208859320,1482862807,1326295511,1181531558,2003814564]
    f = 0x1ffb3dd# 41495333
    print f
    key = f ^ array[0]
    print hex(key ^ array[1])

