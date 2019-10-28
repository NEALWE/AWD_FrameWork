# coding:utf-8

# 作者：nealwe
# 时间：2018/5/24
# 需要实现的功能有 '对/var,/www目录下所有以.php结尾的文件进行waf路径的添加,/home/nealwe_ini.php'

import os
import re
import sys
import time

class Waf():
    def __init__(self):
        pass

    def ALLFilePath(self, back_dir):
        rootdir = [back_dir.replace("*", "")]
        allfile = []
        for i in range(len(rootdir)):
            for dirpath, dirnames, filenames in os.walk(rootdir[i]):
                for dir in dirnames:
                    allfile.append(os.path.join(dirpath, dir))
                for name in filenames:
                    allfile.append(os.path.join(dirpath, name))
        return allfile

    def AddWaf(self, target_file_path, waf_path, ip_filter):
        raw_file = open(target_file_path, 'r+')
        content = raw_file.read()
        waf_sentence = "<?php include(\"" + waf_path + "\");include(\"" + ip_filter + "\");"
        if waf_sentence in content:
            pass
        else:
            content = re.sub(r'<\?\s*php', waf_sentence, content)
            # content = re.sub(waf_sentence,'<\?\s*php', content)
            raw_file.seek(0, 0)
            raw_file.write(content)
            raw_file.close()

    def Mkdir(self):
        try:
            os.system(
                'mkdir /tmp/backup/;mkdir /tmp/backup/website/;mkdir /tmp/backup/mysqlB/;mkdir /tmp/website_forback/;mkdir /tmp/logs/;mkdir /tmp/raw_logs/;')
        except:
            print("backup error")

    # def Varback(self,remote_file_path,back_file_name):
    # def Varback(self, remote_file_path):
    #     try:
    #         # os.system('tar -zcvf {}backup/website/website_var.tar.gz {} > /dev/null 2>&1;'.format(remote_file_path,back_file_name))
    #         # print 'tar -zcvf {}backup/website/website_var.tar.gz /var/www/html/* > /dev/null 2>&1;'.format(remote_file_path)
    #         os.system('su - www-data -c "tar -zcvf {}backup/website/website_var.tar.gz /var/www/html/* > /dev/null 2>&1;"'.format(
    #             remote_file_path))
    #         os.system('cd /tmp/var_forback/;tar -zxvf {}backup/website/website_var.tar.gz > /dev/null 2>&1;'.format(
    #             remote_file_path))
    #     except:
    #         print
    #         "[-] backup error"


    def BackUp(self, remote_file_path, back_dir):
        try:
            os.system('tar -zcvf {}backup/website/website_back_dir.tar.gz {} > /dev/null 2>&1;'.format(remote_file_path, back_dir.strip('\n')))
            os.system('cd /tmp/website_forback/;tar -zxvf {}backup/website/website_back_dir.tar.gz > /dev/null 2>&1;'.format(remote_file_path))
        except:
            print("[-] backup error")


if __name__ == "__main__":

    # Useage: su - www-data -c "python /tmp/stepTar.py /tmp/ /var/www/html"
    #  !!!  : su - www-data -c "python /tmp/stepTar.py /tmp/ /var/www/html/*"  错的！！！！不能有/*

    remote_file_path = sys.argv[1]

    back_dir = sys.argv[2]

    print("[-] 网站备份在 %sbackup/website/\n" % remote_file_path)


    NewWAf = Waf()

    try:

        NewWAf.Mkdir()

    except:

        print("\n[-] 备份所需目录已存在\n")


    allfile = NewWAf.ALLFilePath(back_dir)

    try:

        NewWAf.BackUp(remote_file_path=remote_file_path, back_dir=back_dir)

        BackUp_result = os.popen('ls /tmp/backup/website/website_back_dir.tar.gz').read()

        if "No such file or directory" in BackUp_result:

            print("/var/www/html No such file or directory")

            exit(0)

        elif BackUp_result.strip('\n') == "/tmp/backup/website/website_back_dir.tar.gz":

            print("[*] backup done!")

        else:
            print(BackUp_result)

    except:

        print("{} 备份失败".format(back_dir))

        exit(0)

        pass


    # os.system("find /var/www/html/* | xargs grep -n 'localhost'")

    for file in allfile:

        # print(file)

        if ("config" in file.lower() or "setting" in file.lower() or "ini" in file.lower() or "db" in file.lower()) and "www" in file.lower():

            print("[******************%s****************************]" % file)

            try:

                tmp = open(file, 'r')

                flag = 0

                count = 0

                tmp2 = tmp.readlines()

                for tmp_line in tmp2:

                    line = tmp_line.strip('\n').lower()

                    # if 'localhost' in line or 'db' in line or 'user' in line or 'pass' in line or 'port' in line:
                    if 'localhost' in line or '127.0.0.1' in line or 'database' in line or 'host' in line :

                        flag = 1

                    if flag == 1:

                        print("[***]" + line)

                        count += 1

                    if count == 10:

                        print("[************** this   config   over **************]")

                        print("[**************************************************]")

                        break

            except:

                pass

        try:
            NewWAf.AddWaf(target_file_path=file, waf_path="{}nealwe_ini.php".format(remote_file_path),
                          ip_filter="{}nealwe_ip_filter.php".format(remote_file_path))
        except:

            pass

    # print("please wait 10 seconds")
    # time.sleep(10)

    os.system("tar -zcvf  {}backup_nealwe.tar.gz {}backup/*".format(remote_file_path, remote_file_path))
