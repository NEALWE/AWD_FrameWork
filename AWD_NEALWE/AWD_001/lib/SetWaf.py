# coding:utf-8

# 作者：nealwe
# 时间：2018/5/24
# 需要实现的功能有 '登陆ssh' -> '修改密码' -> '重新登录' -> '执行命令'

import os
import paramiko
import re

class RunWaf():
    def __init__(self):
        pass

    def SSHLogin(self,IP,port,username,password,command):
        # try:
            # ssh = paramiko.SSHClient()
            # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 跳过了远程连接中选择‘是’的环节,
            # ssh.connect(IP, port, username, password)
            # stdin, stdout, stderr = ssh.exec_command('whoami')
            # stdin, stdout, stderr = ssh.exec_command('scp -r /Users/chendang/Downloads/nealwe\ 2/new_awd/test/commands_nealwe.py {}@{}:./commands_nealwe.py.py'.format(username,password,command))
            # scp -r /root/lk root@43.224.34.73:/home/lk/cpfile
            # print stdout.read()
            # pass
        # except:
        #     pass
        # return 0


        t = paramiko.Transport((IP, port))
        t.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(t)
        # 这里的os.path.join 只是个人需要 可以直接sftp.put(local_file_path, remote_file_path)
        sftp.put(os.path.join('/home/update', 'a.txt'), os.path.join('/home/update', 'a.txt'))
        t.close()



    # os.walk()遍历文件夹下的所有文件
    # os.walk()获得三组数据(rootdir, dirname,filnames)
    def FilePath(self, file_dir, dir, file):
        # file_dir 是目标文件夹， dir 是在目标文件中要搜索的文件夹，file 是dir下存在的文件
        # Usage for example : file_path("/Users/apple/Downloads","www","index.php")
        try:
            for root, dirs, files in os.walk(file_dir):
                for subdir in dirs:
                    if dir.lower() == subdir.lower():
                        target_file_path = root + '/' + dir
                        break
                for subfile in files:
                    if target_file_path != '' and target_file_path == root and file.lower() == subfile.lower():
                        target_file_path = target_file_path + '/' + subfile
                        break
            return target_file_path
        except:
            print("[x] Path error!")
            return "[x] Path error!"

    def AddWaf(self, target_file_path, waf_path):
        raw_file = open(target_file_path , 'r+')
        # waf_file = open("file/nealwe.php", 'r')
        content = raw_file.read()
        content = re.sub(r'<\?\s*php', "<?php include(\"" + waf_path + "\");", content)
        raw_file.seek(0, 0)
        raw_file.write(content)
        raw_file.close()
