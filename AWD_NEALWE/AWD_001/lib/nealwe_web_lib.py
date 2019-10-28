# coding:utf-8

import os
import re
import random
import hashlib


def ipv4AddrCheck(ipAddr):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(ipAddr):
        return True
    else:
        return False


def standard_headers(headers):
    headers = headers.strip()
    headers = '{"' + headers.replace(': ', '": "').replace('\n', '",\n"') + '"}'
    return eval(headers)


def portCheck(Port):
    if Port != '' and int(Port) in range(65535):
        return True
    else:
        return False


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


def md5(string):
    m = hashlib.md5()
    m.update(string)
    return m.hexdigest()


def randomMD5():
    tmpstr = str(random.randint(1, 10)) + "1"
    m = hashlib.md5()
    b = tmpstr.encode(encoding='utf-8')
    m.update(b)
    str_md5 = m.hexdigest()
    print(str_md5)
    return str_md5


def mkdir(dir):
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
    except:
        print("[X] {} | CreateFolder Failed!".format(dir))
        exit()

