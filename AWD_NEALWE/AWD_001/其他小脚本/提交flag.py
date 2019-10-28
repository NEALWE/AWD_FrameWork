# coding:utf-8

# 作者：nealwe
# 时间：2018/12/7
# 需要实现的功能有 '读取ip+flag并提交';

import sqlite3
import os
import sys
import paramiko
import re
import time
import json
import requests
import threading
from multiprocessing import Process
import hashlib
import base64
import random


def module_path():
    """
    This will get us the program's directory
    """
    return os.path.dirname(os.path.realpath(__file__))


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

def headers_standard(headers):
    headers = headers.strip()
    headers = '"' + headers.replace(': ', '": "').replace('\n', '",\n"') + '",'
    return headers

def ALLFilePath(rootdir):
    allfile = []
    for dirpath, dirnames, filenames in os.walk(rootdir):
        for dir in dirnames:
            allfile.append(os.path.join(dirpath, dir))
        for name in filenames:
            allfile.append(os.path.join(dirpath, name))
    return allfile

def headers_from_string_dict(data):
    tmp = ""
    split_data = data.split('\n')
    for headers in split_data:
        headers = headers.strip()
        if headers == "":
            continue
        headers = '"' + headers.replace(': ', '": "').replace('\n', '",\n"') + '",'
        if headers == split_data[-1]:
            tmp = tmp + headers
        else:
            tmp = tmp + headers + '\n'
    return eval("{" + tmp + "}")

class flag_sql():
    def __init__(self):
        self.conn = sqlite3.connect(os.path.join(local_file_path, "shell.sqlite"))
        self.c = self.conn.cursor()
        # # print "Opened database successfully"
    def flag_insert(self,flag):
        if len(flag) < 25:
            return 0
        sql = """INSERT INTO "main"."AWD_FLAG" ("flag") VALUES ("{}")""".format(flag)
        # # print sql
        self.c.execute(sql)
        self.conn.commit()
        return 1
    def flag_select(self):
        # cursor = self.c.execute("select id,csrf,flag from csrf_flag where flag>0 and csrf>0 order by id desc;")
        cursor = self.c.execute("select DISTINCT ip, flag, id, csrf from csrf_flag where csrf > 0 and flag > 0 and julianday('now')*86400-julianday(insert_time)*86400 < 50 limit 20")
        # cursor = self.c.execute("select DISTINCT ip, flag, id, csrf from csrf_flag where csrf > 0 and flag > 0 and julianday('now')*86400-julianday(insert_time)*86400 < 50 limit 20 ORDER BY insert_time")
        flags = []
        for row in cursor:
            # # print "id = ", row[0]
            # # print "flag = ", row[1], "\n"
            flag = row[1]
            ip = row[0]
            flags.append([ip,flag])
        return flags
    def flag_update(self, flag):
        # csrf_change = str(random.uniform(10, 20))
        sql2 = """UPDATE "main"."csrf_flag" SET "csrf" = NULL WHERE  "flag" = \"%s\"""" % (flag)
        self.c.execute(sql2)
        self.conn.commit()
    def flag_delete(self, flag):
        self.c.execute("DELETE from COMPANY where ID=2;")
        self.conn.commit()
    def LOG_insert(self,url,flag,send_data,res_data,filepath,line):
        if len(flag) < 20:
            # # print "Record length is too short!"
            return 0
        sql = """INSERT INTO "main"."AWD_LOG" ("url","flag","send_data","res_data","file","line") VALUES ("{}","{}","{}","{}","{}","{}")""".format(url, flag, send_data, res_data, filepath, line)
        # # print sql
        self.c.execute(sql)
        self.conn.commit()
        return 1
    def LOG_select(self):
        cursor = self.c.execute("select id,flag from AWD_FLAG where submit = 0 and outtime = 0 and julianday('now')*86400-julianday(intime)*86400 < 60")  # 60s
        for row in cursor:
            pass
            # print "id = ", row[0]
            # print "flag = ", row[1], "\n"
        # # print "Operation done successfully"
    def LOG_update(self, flag):
        self.c.execute("UPDATE AWD_FLAG SET outtime = datetime('now') where flag = '{}'".format(flag))
        self.conn.commit()
        # print "[*] Total number of rows updated :", self.conn.total_changes
    def LOG_delete(self, flag):
        self.c.execute("DELETE from COMPANY where ID=2;")
        self.conn.commit()
        # print "[*] Total number of rows deleted :", self.conn.total_changes
    def end(self):
        self.conn.close()
        # print "[*] conn end"


    # 插入
    # INSERT INTO "main"."AWD_FLAG" ("flag") VALUES ("test444")
    # 选择出flag
    # select id,flag from AWD_FLAG where submit = 0 and outtime = 0 and julianday('now')*86400-julianday(intime)*86400 < 300
    # UPDATE AWD_FLAG SET outtime = datetime('now') where id = 1
    #
    #
        pass


def mkdir(path):
    # 引入模块
    import os

    # 去除首位空格
    path = path.strip()
    # 去除尾部 \ 符号
    path = path.rstrip("/")

    # 判断路径是否存在
    # 存在     True
    # 不存在   False
    isExists = os.path.exists(path)

    # 判断结果
    if not isExists:
        # 如果不存在则创建目录
        # 创建目录操作函数
        os.makedirs(path)
        return True
    else:
        # 如果目录存在则不创建，并提示目录已存在
        # # print path + ' 目录已存在'
        return False

if __name__ == "__main__" :
    # url = "http://127.0.0.1:6080/ad/hacker/submit/submitCode"
    # curl -i -s -k --data-binary $'token=faae0b01ad245f3f29d0357e03ed0553&ip=172.17.68.201&flag=782eafa5a446d88e1860092a22d423bf' $'http://172.17.68.163:4000/submit'

    url = "http://192.168.100.1/Title/TitleView/savecomprecord"

    headers = """
Host: 192.168.100.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=ud4lftd92dk0ocdoj55lmidb60
X-Forwarded-For: 127.0.0.1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0"""
    headers = headers_from_string_dict(headers)

    sum_webnum = 1
    local_file_path = module_path()
    flag_class = flag_sql()
    # print headers
    while True:
        for webnum in range(sum_webnum):
            ipflags = flag_class.flag_select()
            for ipflag in ipflags:
                ip = ipflag[0]
                flag = ipflag[1]
                # if len(flag) == 37:
                #     print(flag)
                #     pass
                # else:
                #     continue
                try:
                    data = {
                        "answer": flag,
                        # "ip": ip,
                        # "token": "faae0b01ad245f3f29d0357e03ed0553",
                    }
                    print(requests.post(url=url, headers=headers, data=data, timeout=2).text)
                    flag_class.flag_update(flag)
                    time.sleep(0.1)
                except Exception as e:
                    print(e)
                    pass
        time.sleep(0.5)
