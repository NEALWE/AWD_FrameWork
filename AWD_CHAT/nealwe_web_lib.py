# coding:utf-8

import sys
import os
import subprocess
import shlex
import json
import base64
import urllib.parse

from datetime import datetime
import hashlib

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

def write_once(file, write_line):
    f = open(file, 'a+')
    f.write(write_line)
    f.write('\n')
    f.close()


def overwrite_once(file, write_line):
    f = open(file, 'w+')
    f.write(write_line)
    f.write('\n')
    f.close()


def try_mkdir(filename):
    try:
        os.makedirs(filename)
    except Exception as e:
        print(e)


def urlencode(test):
    return urllib.parse.quote(test)


def urldecode(test):
    return urllib.parse.unquote(test)


def json_to_dict(json_str):
    return json.loads(json_str)


def str_to_dict(string):
    return eval(string)


def str_to_byte(string):
    return bytes(string, encoding="utf8")


def byte_to_str(string):
    return str(string, encoding="utf-8")


def input_(config):
    return byte_to_str(base64.b64encode(str_to_byte(str(config))))


def save_targets(save_file, targets=list()):
    for target in targets:
        write_once(save_file, str(target))


def module_path():
    """
    This will get us the program's directory
    """
    return os.path.dirname(os.path.realpath(__file__))


def dict_keys_to_list_keys(dict_keys):
    tmp = []
    for key in dict_keys:
        tmp.append(key)
    return tmp


def md5_py2(str_a):
    '''
    python2
    :param str_a:
    :return:
    '''
    import hashlib
    # 创建md5对象
    m = hashlib.md5()
    # Tips
    # 此处必须encode
    # 若写法为m.update(str)  报错为： Unicode-objects must be encoded before hashing
    # 因为python3里默认的str是unicode
    # 或者 b = bytes(str, encoding='utf-8')，作用相同，都是encode为bytes
    b = str(str_a)
    m.update(b)
    return m.hexdigest()

def md5_py3(str_a):
    '''
    python3
    :param str_a:
    :return:
    '''
    import hashlib
    # 创建md5对象
    m = hashlib.md5()
    # Tips
    # 此处必须encode
    # 若写法为m.update(str)  报错为： Unicode-objects must be encoded before hashing
    # 因为python3里默认的str是unicode
    # 或者 b = bytes(str, encoding='utf-8')，作用相同，都是encode为bytes
    b = str(str_a)
    m.update(b.encode("utf8"))
    return m.hexdigest()

def time_now():
    return str(datetime.now())

