import sys
if __name__ == '__main__':
    if len(sys.argv) < 2:

        print 'no argument'

        sys.exit()

    if sys.argv[1].startswith('--'):

        option = sys.argv[1][2:]


        if option == 'version': 

            print 'Version 1.2.3'

        elif option == 'help':

            print 'help documention'

        else:

            print 'only --version --help can be used'

            sys.exit()

    else:
        for filename in sys.argv[1:]:
            fin = open(filename,"rb").read()
#            print fin.encode('hex')
            fout = open(filename+'.hex',"w")
            fout.write(fin.encode('hex'))
            fout.close()

