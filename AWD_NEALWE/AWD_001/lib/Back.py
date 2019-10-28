# coding:utf-8

# 作者：nealwe
# 时间：2018/5/24
# 需要实现的功能有 '上waf' -> '备份网站+mysql' -> '本地下载并解压'
# waf所在的名称为 nealwe_ini.php

import os
import paramiko
import re
import time
import webbrowser
import socket
import sys
from paramiko.py3compat import u
import termios
import tty

class AWD(object):
    def __init__(self,IP,port,username,password,pkeyfile,WebWorkPath,RemoteFilePath,MysqlUsername,MysqlPassword):
        self.IP = IP
        self.port = int(port)
        self.username = username
        self.password = password
        try:
            self.pkey = paramiko.RSAKey.from_private_key_file(pkeyfile)
        except:
            self.pkey = ''
        self.MysqlUsername = MysqlUsername
        self.MysqlPassword = MysqlPassword
        self.WebWorkPath = WebWorkPath
        self.RemoteFilePath = RemoteFilePath  # 一定要在最后加'/'
        self.sshtransport = None
        self.sshclient = None
        self.sftp = None
        self.pkeyfile = pkeyfile
        try:
            import termios
            import tty
            self.has_termios = True
        except ImportError:
            self.has_termios = False

    def startup(self):
        if self.username != '' and self.password != '':
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 跳过了远程连接中选择‘是’的环节,
                ssh.connect(self.IP, self.port, self.username, self.password)
                self.sshclient = ssh
                print("[*]{}Client连接成功！".format(self.IP))
                t = paramiko.Transport((self.IP, self.port))
                t.connect(username=self.username, password=self.password)
                self.sshtransport = t
                self.sftp = paramiko.SFTPClient.from_transport(self.sshtransport)
                print("[*]{}Transport连接成功！".format(self.IP))
                return 1
            except:
                print("[X]{}-连接失败".format(self.IP))
                return 0
        elif self.pkey != '':
            # 先把pkeyfile给600权限
            os.system("chmod 600 {}".format(self.pkeyfile))
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 跳过了远程连接中选择‘是’的环节,
                ssh.connect(self.IP, self.port, self.username, self.pkey)
                self.sshclient = ssh
                print("[*]{} sshclient连接成功".format(self.IP))
                t = paramiko.Transport((self.IP, self.port))
                t.connect(username=self.username, pkey=self.pkey)
                self.sshtransport = t
                self.sftp = paramiko.SFTPClient.from_transport(self.sshtransport)
                print("[*]{} SFTPClient连接成功！".format(self.IP))
                return 1
            except:
                print("[X]{} sshclient or SFTPClient连接失败".format(self.IP))
                return 0
        else:
            print ("[X funtion() startup error X]{}".format(self.IP))
            return 0

    def interactive_shell(self, chan):
        if self.has_termios:
            self.posix_shell(chan)
        else:
            self.windows_shell(chan)

    def posix_shell(self, chan):
        import select

        oldtty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            chan.settimeout(0.0)

            while True:
                r, w, e = select.select([chan, sys.stdin], [], [])
                if chan in r:
                    try:
                        x = u(chan.recv(1024))
                        if len(x) == 0:
                            sys.stdout.write("\r\n*** EOF\r\n")
                            break
                        sys.stdout.write(x)
                        sys.stdout.flush()
                    except socket.timeout:
                        pass
                if sys.stdin in r:
                    x = sys.stdin.read(1)
                    if len(x) == 0:
                        break
                    chan.send(x)

        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)

    # thanks to Mike Looijmans for this code
    def windows_shell(self, chan):
        import threading

        sys.stdout.write(
            "Line-buffered terminal emulation. Press F6 or ^Z to send EOF.\r\n\r\n"
        )

        def writeall(sock):
            while True:
                data = sock.recv(256)
                if not data:
                    sys.stdout.write("\r\n*** EOF ***\r\n\r\n")
                    sys.stdout.flush()
                    break
                sys.stdout.write(data)
                sys.stdout.flush()

        writer = threading.Thread(target=writeall, args=(chan,))
        writer.start()

        try:
            while True:
                d = sys.stdin.read(1)
                if not d:
                    break
                chan.send(d)
        except EOFError:
            # user hit ^Z or F6
            pass

    def Interactive(self):
        paramiko.util.log_to_file('./log')
        # 建立交互式shell连接
        channel = self.sshclient.invoke_shell()
        # 建立交互式管道
        self.interactive_shell(channel)
        # return channel

    def ALLFilePath(self, rootdir):
        allfile = []
        for dirpath, dirnames, filenames in os.walk(rootdir):
            for dir in dirnames:
                allfile.append(os.path.join(dirpath, dir))
            for name in filenames:
                allfile.append(os.path.join(dirpath, name))
        return allfile

    def Uploadfiles(self):
        print ('start upload files')
        local_all_files = self.ALLFilePath(self.WebWorkPath+"Uploadfiles")
        for file in local_all_files:
            if "backforwad.tar.gz" in file:
                continue
            # print ('[*]uploading: \t', file, "\n\t\t\tto:\t---->\t",self.RemoteFilePath+file.split('/')[-1])
            try:
                self.sftp.put(file, self.RemoteFilePath + file.split('/')[-1])
            except:
                print ("[-]upload failed : %s"%file)

    def UploadOnefile(self, file):
        print ('start upload file')
        print ('[*]uploading: \t', file, "\n\t\t\tto:\t---->\t",self.RemoteFilePath+file.split('/')[-1])
        self.sftp.put(file,self.RemoteFilePath+file.split('/')[-1])

    def DownRemotefile(self):
        fromfile = "{}backup_nealwe.tar.gz".format(self.RemoteFilePath)
        tofile = os.path.join(self.WebWorkPath, 'Remotefiles/html/backup_nealwe.tar.gz')
        print(fromfile)
        print(tofile)
        self.sftp.get(fromfile, tofile)

    def RunPythonCommands_nealwe(self):
        try:
            stdin, stdout, stderr = self.sshclient.exec_command('ls {}'.format(self.RemoteFilePath))
            if "nealwe.py" in stdout.read():
                print ("[*]upload end!\n\n\n[*]开始打包网站并部署waf\n\n\n")
                pycommand = 'python {}commands_nealwe.py {} '.format(self.RemoteFilePath,self.RemoteFilePath)
                _stdin, _stdout, _stderr = self.sshclient.exec_command(pycommand)
                print (_stdout.read())
            else:
                print("[-]upload failed !")
                input("回车继续")
        except:
            pass
        return 0

    def SSHexec(self, command): # 有回显
        try:
            _stdin, _stdout, _stderr = self.sshclient.exec_command(command)
            print(str(_stdout.read(), encoding="utf8"))
            return 1
        except:
            print(command + " execute error")
            return 0
    def _SSHexec(self, command): # 无回显
        try:
            _stdin, _stdout, _stderr = self.sshclient.exec_command(command)
            return str(_stdout.read(), encoding="utf8")
        except:
            print(command + " execute error")
            return 0


    def MysqlBackUp(self):
        MysqlUsername, MysqlPassword = '', ''
        try:
            # MysqlUsername, MysqlPassword = open('mysql.txt', 'r').read().split(' ')
            MysqlUsername, MysqlPassword = "root", "root"
            print("MysqlUsername: \"{}\"\nMysqlPassword: \"{}\"".format(MysqlUsername, MysqlPassword))
            reset_flag = input("需要重置Mysql用户名和密码吗?[y/N]").lower() or 'n'
        except:
            reset_flag = 'y'
            pass
        if reset_flag == 'y':
            MysqlUsername, MysqlPassword = input("MYsql username\n"), input("MYsql passwd\n")
            # open('mysql.txt', 'w+').write(MysqlUsername + " " + MysqlPassword)
        if MysqlUsername == '' and MysqlPassword == '':
            print("请重新查找 MysqlUsername, MysqlPassword。")
            exit()
        try:
            stdin, stdout, stderr = self.sshclient.exec_command("mkdir {}backup/mysqlB/;mysqldump -u {} -p{} --all-databases > {}backup/mysqlB/all.sql; " .format(self.RemoteFilePath, MysqlUsername, MysqlPassword, self.RemoteFilePath))
            print(stdout.read())
        except:
            print("error")

    def shutdown(self):
        if self.sshtransport:
            self.sshtransport.close()
            # print('[-] disconnect server: %s!' % self.IP)
            self.sshtransport = None
        if self.sftp:
            self.sftp.close()
            # print('[-] disconnect sftp server: %s!' % self.IP)
            self.sftp = None
        if self.sshclient:
            self.sshclient.close()
            # print('[-] disconnect sshclient server: %s!' % self.IP)
            self.sshclient = None


            # 处理上传

