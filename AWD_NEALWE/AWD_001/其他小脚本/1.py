import hashlib
import os
from config import *


def module_path():
    """
    This will get us the program's directory
    """
    return os.path.dirname(os.path.realpath(__file__))



def md5(s):
    m = hashlib.md5()
    m.update(s.encode())
    return m.hexdigest()


def gen_passwd(ip):
    passwd = md5("jspi" + str(ip) + "nealwe_NEALWE")
    return passwd


def ip_list(x):
    ipList = []
    iplist = x.split('.')
    if '-' in x:
        for i in iplist:
            d = i
            if '-' in d:
                p = iplist.index(d)
                l = d.split('-')
                m = int(l[0])
                n = int(l[1])
        for j in range(m, n + 1):
            iplist[p] = str(j)
            ip = '.'.join(iplist)
            ipList.append(ip)
        ipList = sorted(set(ipList), key=ipList.index)  # 去重
    else:
        ip = '.'.join(iplist)
        ipList.append(ip)
        ipList = sorted(set(ipList), key=ipList.index)
    return ipList

f = open(os.path.join(module_path(), "ips.log"), 'w')
for ip in ip_list(ips):
    password = gen_passwd(ip)
    f.write(f"ip: {ip} password: {password}\n")
f.close()