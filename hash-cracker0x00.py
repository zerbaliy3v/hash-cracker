import sys
import time
import hashlib

if len(sys.argv) == 3:
            args = sys.argv[1]
            wordlist = sys.argv[2]
elif sys.argv[1] == '--help' or sys.argv[1] == '-h':
    sys.exit('''Help information:
 		@zerbaliy3v           
python hash-cracker0x00.py  <enter hash> <wordlist>
python hash-cracker0x00.py  de6838252f95d3b9e803b28df33b4baa rockyou.txt
''')
    
else:
    sys.exit('''\nhash.py --help -h help description\npython hash-cracker0x00.py  <enter hash> <wordlist>\n''')
                 
def hashing(algorithm):
    with open(wordlist, 'r') as f:
        password = f.read().splitlines()
        p = []
        for i in password:  
            i = str(i) 
            
            #time.sleep(1)
            if algorithm == 'md5':
                if hashlib.md5(i.encode()).hexdigest() == args:
                    print('[+] @Hash Algoritm:{} @Password Found:<<{}>>'.format('md5',i),' @Hash:<<{}>>'.format(args))
                    p.append(hashlib.md5(i.encode()).hexdigest())
                break
            elif algorithm == 'sha1':
                if hashlib.sha1(i.encode()).hexdigest() == args:
                    print('[+] @Hash Algoritm:{} @Password Found:<<{}>>'.format('sha1',i),' @Hash:<<{}>>'.format(args))
                    p.append(hashlib.sha1(i.encode()).hexdigest())
                break 
            elif algorithm == 'sha256':
                if hashlib.sha256(i.encode()).hexdigest() == args:
                    print('[+] @Hash Algoritm:{} @Password Found:<<{}>>'.format('sha256',i),' @Hash:<<{}>>'.format(args))
                    p.append(hashlib.sha256(i.encode()).hexdigest())
                break
            elif algorithm == 'sha512':
                if hashlib.sha512(i.encode()).hexdigest() == args:
                    print('[+] @Hash Algoritm:{} @Password Found:<<{}>>'.format('sha512',i),' @Hash:<<{}>>'.format(args))
                    p.append(hashlib.sha512(i.encode()).hexdigest())
                break 
            elif algorithm == 'blake2s':
                if hashlib.blake2s(i.encode()).hexdigest() == args:
                    print('[+] @Hash Algoritm:{} @Password Found:<<{}>>'.format('blake2s',i),' @Hash:<<{}>>'.format(args))
                    p.append(hashlib.blake2s(i.encode()).hexdigest())
                break
            elif algorithm == 'blake2b':
                if hashlib.blake2b(i.encode()).hexdigest() == args:
                    print('[+] @Hash Algoritm:{} @Password Found:<<{}>>'.format('blake2b',i),' @Hash:<<{}>>'.format(args))
                    p.append(hashlib.blake2b(i.encode()).hexdigest())
                break    
        if not(args in p):
            print('[-] @Password Don\'t Fond! @Hash:<<{}>>'.format(args))   
try:
        print(
    '''
    Select Hash Algorithms

    1- md5
    2- sha1
    3- sha256
    4- sha512
    5- blake2s
    6- blake2b

    ''')
        algorithm = int(input("Enter algorithm: "))
            
        if args == '-h' or args == '--help':
            print(
        '''
        hash.py --help -h help 
        hash.py <enter hash> 
        '''
        )
        elif algorithm ==1:
            hashing('md5')
        elif algorithm ==2:
            hashing('sha1')
        elif algorithm ==3:
            hashing('sha256')
        elif algorithm ==4:
            hashing('sha512')
        elif algorithm ==5:
            hashing('blake2s')
        elif algorithm ==6:
            hashing('blake2n')  
        else:
            sys.exit("Invalid algorithm")     
except Exception as e :
    print("Error: " + str(e))
    print('python hash-cracker0x00.py  <enter hash> <wordlist>')