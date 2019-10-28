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


class flag_sql():
    def __init__(self):
        self.conn = sqlite3.connect('{}shell.sqlite'.format(local_file_path))
        self.c = self.conn.cursor()
        # print "Opened database successfully"
    def flag_insert(self,flag):
        if len(flag) < 25:
            return 0
        sql = """INSERT INTO "main"."AWD_FLAG" ("flag") VALUES ("{}")""".format(flag)
        # print sql
        self.c.execute(sql)
        self.conn.commit()
        print "Records created successfully"
        return 1
    def flag_select(self):
        cursor = self.c.execute("select id,csrf,flag from csrf_flag where flag>0 and csrf>0 order by id desc;")
        flags = []
        for row in cursor:
            # print "id = ", row[0]
            # print "flag = ", row[1], "\n"
            flags.append(row[2])
        print "Operation done successfully"
        return flags
    def flag_update(self, flag):
        # csrf_change = str(random.uniform(10, 20))
        sql2 = """UPDATE "main"."csrf_flag" SET "csrf" = NULL WHERE  "flag" = \"%s\"""" % (flag)
        self.c.execute(sql2)
        self.conn.commit()
        print "Total number of rows updated :", self.conn.total_changes
    def flag_delete(self, flag):
        self.c.execute("DELETE from COMPANY where ID=2;")
        self.conn.commit()
        print "Total number of rows deleted :", self.conn.total_changes
    def LOG_insert(self,url,flag,send_data,res_data,filepath,line):
        if len(flag) < 20:
            # print "Record length is too short!"
            return 0
        sql = """INSERT INTO "main"."AWD_LOG" ("url","flag","send_data","res_data","file","line") VALUES ("{}","{}","{}","{}","{}","{}")""".format(url, flag, send_data, res_data, filepath, line)
        # print sql
        self.c.execute(sql)
        self.conn.commit()
        print "LOG_insert successfully"
        return 1
    def LOG_select(self):
        cursor = self.c.execute("select id,flag from AWD_FLAG where submit = 0 and outtime = 0 and julianday('now')*86400-julianday(intime)*86400 < 300")
        for row in cursor:
            print "id = ", row[0]
            print "flag = ", row[1], "\n"
        # print "Operation done successfully"
    def LOG_update(self, flag):
        self.c.execute("UPDATE AWD_FLAG SET outtime = datetime('now') where flag = '{}'".format(flag))
        self.conn.commit()
        print "[*] Total number of rows updated :", self.conn.total_changes
    def LOG_delete(self, flag):
        self.c.execute("DELETE from COMPANY where ID=2;")
        self.conn.commit()
        print "[*] Total number of rows deleted :", self.conn.total_changes
    def end(self):
        self.conn.close()
        print "[*] conn end"


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
        # print path + ' 目录已存在'
        return False

if __name__ == "__main__" :
    # url = "http://127.0.0.1:6080/ad/hacker/submit/submitCode"
    url = "http://172.91.1.12:9090/ad/hacker/submit/submitCode"
    cookie = "JSESSIONID=EFC1AB95A128C62CE7C9E79BBAA1A63E"
    headers = {
        "Host": "172.91.1.12:9090",
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Referer": "http://172.91.1.12:9090/arace/index",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Length": "8",
        "Cookie": cookie,
        "Connection": "keep-alive" }
    data = "flag={}"
    # print requests.post(url=url, headers=headers, data=data.format("877749cc46e3c2f792562bdd7f6017b3b886096782b53e1cb87d7238c9129436e9bf0bcb2bbf8da0505cab608bb994cf21d4b907892ded595cf3c3b30c90406b10a5048b3284813236cf88fcbd98898a89d28b0c8bf04c6f55d9b92462491f16")).content
    # print requests.post(url=url, headers=headers, data=data.format("123", "flag=123"), timeout=2).content
    # exit(0)
    ctf_name = "pcb"
    sum_webnum = 1
    local_file_path = '/home/nealwe/Desktop/nealwe/AWD-share/AWD/AWD_001/ReserveShellManager/'
    print local_file_path
    flag_class = flag_sql()
    while True:
        for webnum in range(sum_webnum):

            ipflags = flag_class.flag_select()
            print ipflags
            # exit(0)
            for ipflag in ipflags:
                if len(ipflag) < 40:
                    # print "over"
                    continue
                else:
                    pass
                    # print "have flag"
                # ip = ipflag.split("#&&#")[0]
                # flag = ipflag.split("#&&#")[1].strip("\n")
                if len(ipflag)>192:
                    ipflag = ipflag[0:192]
                print len(ipflag)
                # exit(0)
                # print local_file_path + ip + "\t" + flag
                try:
                    print requests.post(url=url, headers=headers, data=data.format(ipflag), timeout=2).content
                    flag_class.flag_update(ipflag)
                except:
                    pass
                time.sleep(1.5)
        time.sleep(10)
    # flag_remote_path = "/tmp/.webshell_flags"
    # flag_local_path = "./flags/flags.txt"
    #
    #
    # ctf_name = "pcb"
    # webnum = '0'
    # local_file_path = '/home/nealwe/Desktop/nealwe/AWD-share/AWD/AWD_001/CTFs/{}/{}/'.format(ctf_name, webnum)
    # PcaplogsFolder = local_file_path + "Remotefiles/pcap/tmp/Pcaplogs/"
    # Attack_IPS_list = local_file_path + "Config/IPS_list.txt"
    # tmp_my_ssh = open(local_file_path + 'Config/ssh.txt', 'r')
    # my_ssh = tmp_my_ssh.read().split(',')
    # tmp_my_ssh.close()
    # IP, port, username, password, pkeyfile, remote_file_path = my_ssh[0], my_ssh[1], my_ssh[2], my_ssh[3], my_ssh[4], my_ssh[5]
    # mysql_username = ''
    # mysql_password = ''
    # a = AWD(IP=IP, port=port, username=username, password=password, pkeyfile=pkeyfile,
    #         local_file_path=local_file_path, remote_file_path=remote_file_path, mysql_username=mysql_username,
    #         mysql_password=mysql_password)
    # a.startup()
    # a.DownRemotefile(flag_remote_path, flag_local_path)
