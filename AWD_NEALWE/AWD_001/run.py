#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2018/09/23 10:49
# @Author  : nealwe
# @File    : run.py

import os
import re
import paramiko
import sys
from lib import Back, interactive
from lib.nealwe_web_lib import *
import random
import hashlib



def createFolders_copyUploadFiles(CTFname):
    mkdir(CTFname + '/' + str(i))
    mkdir(CTFname + '/' + str(i) + '/' + 'Remotefiles')
    mkdir(CTFname + '/' + str(i) + '/' + 'Remotefiles' + '/' + 'html')
    mkdir(CTFname + '/' + str(i) + '/' + 'Remotefiles' + '/' + 'pcap')
    mkdir(CTFname + '/' + str(i) + '/' + 'Remotefiles' + '/' + 'Attcker_upload_files')
    # mkdir(CTFname + '/' + str(i) + '/' + 'download')
    # mkdir(CTFname + '/' + str(i) + '/' + 'download' + '/' + 'website')
    mkdir(CTFname + '/' + str(i) + '/' + 'Uploadfiles')
    mkdir(CTFname + '/' + str(i) + '/' + 'Config')
    mkdir(CTFname + '/' + str(i) + '/' + 'Webshell')
    os.system("cp -rf uploadfiles/* {}/{}/Uploadfiles".format(CTFname, str(i)))
    os.system("cp AWD_nealwe_sqlite_Sample.sqlite {}/{}/AWD_nealwe_sqlite.sqlite".format(CTFname, str(i)))


def sshConfig(CTFname, i):
    try:
        ConfigFilePath = CTFname + '/' + str(i) + '/' + 'Config' + '/' + 'ssh.txt'
        my_ssh = open(ConfigFilePath, 'r')
        sshinformation = my_ssh.read()
        if sshinformation.strip('\n') == '':
            pass
        print("\n[*]web {} ssh information : \n-->\t{}".format(i, sshinformation))
        my_ssh.close()
    except:
        sshConfigReset(CTFname, i)
    # try:
    #     my_ssh = open(ConfigFilePath, 'r')
    #     sshinformation = my_ssh.read()
    #     if sshinformation.strip('\n') == '':
    #         pass
    #     print("\n[*]web {} ssh information : \n-->\t{}".format(i, sshinformation))
    #     my_ssh.close()
    #     reset_flag = input("需要重置SSH吗?[Y/n] ").lower() or "y"
    # except:
    #     reset_flag = 'y'
    # if reset_flag == 'n':
    #     return 0


def sshConfigReset(CTFname, i):
    ConfigFilePath = CTFname + '/' + str(i) + '/' + 'Config' + '/' + 'ssh.txt'
    f = open(ConfigFilePath, 'w')  # 10.0.94.3,22,ctf,JSPICST...,,/tmp/
    IP, Port, Username, Password, PkeyFilePath, RemotePathToUpload = "", "", "", "", "", ""
    while not ipv4AddrCheck(IP):
        IP = input("Web {} IP is : ".format(str(i)))
    while not portCheck(Port):
        Port = input("Web {} SSH Port is : ".format(str(i)))
    while not ((Username != '' and Password != '') or PkeyFilePath != ''):
        Username = input("Web {} Username is : ".format(str(i)))
        Password = input("Web {} Password is : ".format(str(i)))
        PkeyFilePath = input("Web {} PkeyFilePath is : ".format(str(i)))
    RemotePathToUpload = "/tmp/"
    f.write(IP + "," + Port + "," + Username + "," + Password + "," + PkeyFilePath + "," + RemotePathToUpload)
    f.close()


def uploadfiles(slave):
    if slave:
        UploadFlag = input("[*]Need Upload ? [Y/n]").lower() or "y"
        ewFlag = input("[*]Need Exec ew on 4396 ? [Y/n]").lower() or "y"
        # reserveShellFlag = input("[*]reserver shell run on 44396 ?").lower() or "y"

        if UploadFlag == 'y':
            slave.Uploadfiles()
            # 给脚本x执行权限
            slave._SSHexec("chmod -R +x /tmp/*;")
            slave._SSHexec("cd /tmp;tar -zxvf /tmp/Reserve.tar.gz & ")
            slave._SSHexec("chmod -R +x /tmp/*;")
        if ewFlag == 'y':
            slave._SSHexec("/tmp/ew_linux_x64 -s ssocksd -l 4396 >/tmp/ew.logs & ")
        # slave._SSHexec("cd /tmp/Reverse-Shell-Manager/build/Reverse-Shell-Manager;")
        return 1
    else:
        return 0


def sshConnect(CTFname, i):
    WebWorkPath = CTFname + '/' + str(i) + '/'
    ConfigFilePath = WebWorkPath + '/' + 'Config' + '/' + 'ssh.txt'
    my_ssh = open(ConfigFilePath, 'r').read().split(',')
    IP, port, username, password, pkeyfile, RemoteFilePath = my_ssh[0], int(my_ssh[1]), my_ssh[2], my_ssh[3], my_ssh[4], \
                                                             my_ssh[5]
    # RemoteFilePath = '/tmp/'  # 一定要在最后加'/'。   注意⚠️：远程所有文件都在这儿了
    MysqlUsername = ''
    MysqlPassword = ''
    a = Back.AWD(IP=IP, port=port, username=username, password=password, pkeyfile=pkeyfile, WebWorkPath=WebWorkPath,
                 RemoteFilePath=RemoteFilePath, MysqlUsername=MysqlUsername, MysqlPassword=MysqlPassword)
    a.startup()
    return a
    # return channel, ssh


def checkSSHAlive(a):
    return a._SSHexec("pwd")


def sshInteractive(a):
    a.Interactive()


def sshEnd(a):
    a.shutdown()


def showSshs(slaves):
    for key, value in slaves.items():
        if checkSSHAlive(slaves[key]):
            print("[*] WEB {} alive".format(key))
    pass


def showDir(slave, Dirlist):
    # Dirlist = ["/var/www/html/*", "/home/wwwroot/*", "/app/*", "/usr/local/nginx/html/*"]
    i = -1
    for dir in Dirlist:
        result_ls = slave._SSHexec("ls {}".format(dir))
        result_ll = slave._SSHexec("ls -l {}".format(dir.replace("/*", "")))
        if result_ls.strip('\n') == "":
            i += 1
            continue
        i += 1
        try:
            print("[{}] Try list details[command ls -l] : ".format(str(i)) + dir + "\t\t" + '\n' + result_ll)
        except:
            print("[-] Not found" + dir)

        try:
            print("[{}] Find Files [list one file] : ".format(str(i)) + dir + "\t\t" + '\n' + result_ls.split("\n")[0])
        except:
            print("[-] Not found" + dir )


def getOwner(slave, file):
    command = "python /tmp/get_owner.py {}".format(file)
    # print(command)
    Owner = slave._SSHexec(command)
    # Owner = str(Owner, encoding="utf8")
    print("[*] {} :".format(file) + Owner)
    return Owner.strip('\n')

def downSelectDir(slave, DownloadDirOwner, SelectDir, Dirlist, RemoteFilePath=''):
    # Dirlist = ["/var/www/html/*", "/home/wwwroot/*", "/app/*", "/usr/local/nginx/html/*"]
    remote_file_path = "/tmp/"
    back_dir = Dirlist[SelectDir].replace("/*", "")

    command = 'su - {} -c "python /tmp/stepTar.py {} {}" > /tmp/downSelectDir.log'.format(DownloadDirOwner, remote_file_path, back_dir)
    # command = "python /tmp/stepTar.py {} {} {} > /tmp/downSelectDir.log".format(DownloadDirOwner, remote_file_path, back_dir)
    try:
        print("[*]" + command)
        slave.SSHexec(command)  # 备份 html
        logname = "./logs/" + randomMD5()
        slave.sftp.get("/tmp/downSelectDir.log", "{}".format(logname))
        os.system("cat " + logname)
        if os.path.getsize(logname) < 10:
            command = "python /tmp/stepTar.py {} {} > /tmp/downSelectDir.log".format(remote_file_path, back_dir)
            print("[*]" + command)
            slave.SSHexec(command)  # 备份 html
            logname = "./logs/" + randomMD5()
            slave.sftp.get("/tmp/downSelectDir.log", "{}".format(logname))
            if os.path.getsize(logname) < 10:
                print("备份网站出了点问题，有可能waf还挂了，注意把 uploadfiles/nealwe_ini.php 置空")
            else:
                os.system("cat " + logname)
        slave.MysqlBackUp()  # 备份 mysql
        try:
            slave.DownRemotefile()
            print("下载成功！")
        except:
            print("下载失败！手动下载吧！")
            sys.exit()
    except:
        print("[-] backup error")
        return 0


def MysqlBackUp(slave, RemoteFilePath):
    MysqlUsername, MysqlPassword = '', ''
    try:
        # MysqlUsername, MysqlPassword = open('mysql.txt', 'r').read().split(' ')
        MysqlUsername, MysqlPassword = "root", "rDy4gk#Yj^Z@PC%P"
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
        stdin, stdout, stderr = slave.SSHexec("mkdir {}backup/mysqlB/;mysqldump -u {} -p{} --all-databases > {}backup/mysqlB/all.sql; " .format(RemoteFilePath, MysqlUsername, MysqlPassword, RemoteFilePath))
        print (stdout.read())

    except:
        print("error")

def showCommand():
    print("Commands : ")
    print("0.  [0|h|help|?]                                 :    show this help")
    print("1.  [1|g|go]                                     :    goto a slave")
    print("2.  [2|d|dwebsite|download website]              :    tar and download website and add waf")
    print("3.  [3|u|upload]                                 :    upload need files [Default : uploadfiles]")
    print("4.  [4|c|command]                                :    run one command in a slave")
    print("5.  [5|l|list|list all slaves]                   :    list all slaves")
    print("6.  [6|a4|ac|acommand]                           :    run one command in all slave")
    print("7.  [7|daw|dawebsites|download all websites]     :    download html from all slaves")
    # print("8.  [8|daw|dawebsites|download all websites]     :    download html from all slaves")
    print("17. [q|quit|exit]                                :    exit")



if __name__=="__main__":
    RemoteFilePath = "/tmp/"
    slaves = {}     # 所有的ssh链接
    masters = {}
    print("AWD start!")
    CTFname = "CTFs" + "/" + str(input("CTF NAME : "))
    mkdir(CTFname)
    WebNum = input("Sum of Web : ")
    Dirlist = ["/var/www/html/*", "/home/wwwroot/*", "/app/*", "/usr/local/nginx/html/*"]

    # 录入ssh信息
    for i in range(int(WebNum)):
        createFolders_copyUploadFiles(CTFname)
        # sshConfig(CTFname, i)
        slaves[i] = ""
        while slaves[i] == "":
            sshConfig(CTFname, i)
            try:
                slaves[i] = sshConnect(CTFname, i)
            except:
                slaves[i] = ""
                continue
            uploadfiles(slaves[i])

    showCommand()
    while True:
        command = input(">>>please input command:").lower()
        if command == "0" or command == "h" or command == "help" or command == "?":
            showCommand()

        elif command == "1" or command == "g" or command == "go":
            try:
                showSshs(slaves)
                slavernumber = input("\ninput slaver number:")
                slave = slaves[int(slavernumber.strip('\n'))]
                sshInteractive(slave)
            except:
                print("input right slaver number:")

        elif command == "2" or command == "d" or command == "dwebsite" or command == "download website":
            # su - www-data -c "python /tmp/commands_nealwe.py /tmp/"
            DownloadDirOwner = ""
            try:
                showSshs(slaves)
                slavernumber = input("\n[*]Download...\ninput slaver number:")
                slave = slaves[int(slavernumber.strip('\n'))]
                print("[*]show dir")
                showDir(slave, Dirlist)
                SelectDir = int(input("\n[*]Download Select Dir : "))
                DownloadDirOwner = getOwner(slave, Dirlist[SelectDir])
                downSelectDir(slave, DownloadDirOwner, SelectDir, Dirlist, RemoteFilePath)
                # MysqlBackUp(slave, RemoteFilePath)
            except:
                print("input right slaver number:")
                try:
                    print("[*]su - {} -c \"python /tmp/commands_nealwe.py /tmp/\"".format(DownloadDirOwner))
                except:
                    print("[*]su - {} -c \"python /tmp/commands_nealwe.py /tmp/\"")



        elif command == "3" or command == "u" or command == "upload":
            showSshs(slaves)
            slavernumber = input("\n[*]Upload...\ninput slaver number:")
            slave = slaves[int(slavernumber.strip('\n'))]
            try:
                uploadfiles(slave)
            except:
                pass

        elif command == "4" or command == "c" or command == "command":
            showSshs(slaves)
            slavernumber = input("\n[*]Command...\ninput slaver number:")
            slave = slaves[int(slavernumber.strip('\n'))]
            command = input("input command:\n")
            try:
                slave.SSHexec(command)
            except:
                pass

        elif command == "5" or command == "l" or command == "list" or command == "list all slaves":
            try:
                showSshs(slaves)
            except:
                print("[XXX]ssh error!")

        elif command == "6" or command == "a4" or command == "ac" or command == "acommand":
            command = input("input command:\n")
            for key, value in slaves.items():
                # slave = slaves[key]
                slave = value
                try:
                    slave.SSHexec(command)
                except:
                    pass

        elif command == "7" or command == "daw" or command == "dawebsites" or command == "download all websites":
            for key, value in slaves.items():
                # slave = slaves[key]
                slave = value
                try:
                    showDir(slave, Dirlist)
                    SelectDir = int(input("\n[*]Download Select Dir : "))
                    DownloadDirOwner = getOwner(slave, Dirlist[SelectDir])
                    downSelectDir(slave, DownloadDirOwner, SelectDir, Dirlist)
                except:
                    pass

        elif command == "q" or command == "quit" or command == "exit":
            exit(0)



















