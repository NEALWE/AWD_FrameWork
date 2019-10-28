# coding:utf-8

# 作者：nealwe
# 时间：2018/5/24
# 需要实现的功能有 '对/var,/www目录下所有以.php结尾的文件进行waf路径的添加,/home/nealwe_ini.php'

import os
import re
import sys

class Waf():
    def __init__(self):
        pass

    def ALLFilePath(self):
        rootdir = ["/home", "/var/www/"]
        allfile = []
        for i in range(len(rootdir)):
            for dirpath, dirnames, filenames in os.walk(rootdir[i]):
                for dir in dirnames:
                    allfile.append(os.path.join(dirpath, dir))
                for name in filenames:
                    allfile.append(os.path.join(dirpath, name))
        return allfile

    def AddWaf(self, target_file_path, waf_path,ip_filter):
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
            os.system('mkdir /tmp/backup/;mkdir /tmp/backup/website/;mkdir /tmp/backup/mysqlB/;mkdir /tmp/var_forback/;mkdir /tmp/home_forback/;mkdir /tmp/forback/;mkdir /tmp/logs/;mkdir /tmp/raw_logs/;')
        except:
            print "backup error"

    # def Varback(self,remote_file_path,back_file_name):
    def Varback(self,remote_file_path):
        try:
            # os.system('tar -zcvf {}backup/website/website_var.tar.gz {} > /dev/null 2>&1;'.format(remote_file_path,back_file_name))
            # print 'tar -zcvf {}backup/website/website_var.tar.gz /var/www/html/* > /dev/null 2>&1;'.format(remote_file_path)
            os.system('tar -zcvf {}backup/website/website_var.tar.gz /var/www/html/* > /dev/null 2>&1;'.format(remote_file_path))
            os.system('cd /tmp/var_forback/;tar -zxvf {}backup/website/website_var.tar.gz > /dev/null 2>&1;'.format(remote_file_path))
        except:
            print "[-] backup error"

    def Homeback(self,remote_file_path,back_file_name):
        try:
            os.system('tar -zcvf {}backup/website/website_home.tar.gz {} > /dev/null 2>&1; '.format(remote_file_path,back_file_name))
            os.system('cd /tmp/home_forback/;tar -zxvf {}backup/website/website_home.tar.gz > /dev/null 2>&1;'.format(remote_file_path))
        except:
            print "[-] backup error"




if __name__=="__main__":

    remote_file_path = "/tmp/"

    print "[-] 网站备份在 %sbackup/website/\n"%remote_file_path

    NewWAf = Waf()

    try:

        NewWAf.Mkdir()

    except:

        print "\n[-] 备份所需目录已存在\n"

    Varback_flag = 1

    Homeback_flag = 1

    allfile = NewWAf.ALLFilePath()

    try:

        NewWAf.Varback(remote_file_path=remote_file_path)

        Varback_result = os.popen('ls /tmp/backup/website/website_var.tar.gz').read()

        if "No such file or directory" in Varback_result:

            print("/var/www/html No such file or directory")

            exit(0)

        elif Varback_result == "/tmp/backup/website/website_var.tar.gz":

            print("[*] var backup done!")

            Varback_flag = 0

    except:

        print "/var/www/html 备份失败"

        exit(0)

        pass
    # NewWAf.Varback(remote_file_path=remote_file_path)

    # os.system("find /var/www/html/* | xargs grep -n 'localhost'")

    for file in allfile:

        # print allfile

        # if ("index.php" in file.lower() or "config.php" in file.lower()) and "www" in file.lower() and "nealwe" not in file:
        if ".php" in file.lower() and "www" in file.lower() and "nealwe" not in file:

            if Homeback_flag==1 and "home" in file.lower():

                print "[-] 网站路径：" + file

                back_file_name = '/' + file.split('/')[1] + '/' + file.split('/')[2] + '/*'

                print "\n[-] 备份中： %s\n" % back_file_name


                NewWAf.Homeback(remote_file_path=remote_file_path,back_file_name=back_file_name)

                Homeback_flag = 0

            # elif "index.php" in file.lower() or "config.php" in file.lower() :
            #     try:
            #
            #         NewWAf.AddWaf(target_file_path=file, waf_path="{}nealwe_ini.php".format(remote_file_path),
            #                       ip_filter="{}nealwe_ip_filter.php".format(remote_file_path))
            #
            #     except:
            #
            #         pass

        if ("config" in file.lower() or "ini" in file.lower() or "db" in file.lower() )and "www" in file.lower() :

            print "[******************%s****************************]"%file

            try:

                tmp = open(file,'r')

                flag = 0

                count = 0

                tmp2 = tmp.readlines()

                for tmp_line in tmp2:

                    line = tmp_line.strip('\n').lower()

                    # if 'localhost' in line or 'db' in line or 'user' in line or 'pass' in line or 'port' in line:

                    if 'localhost' in line or '127.0.0.1' in line:

                        flag = 1

                    if flag == 1:

                        print "[***]"+line

                    # count += 1

                    # if count == 10:
                    #
                    #     print "[************** this   config   over **************]"
                    #
                    #     print "[**************************************************]"
                    #
                    #     break

                print "[************** this   config   over **************]"

                print "[**************************************************]"

            except:

                pass


        try:
            NewWAf.AddWaf(target_file_path=file, waf_path="{}nealwe_ini.php".format(remote_file_path),
                          ip_filter="{}nealwe_ip_filter.php".format(remote_file_path))
        except:
            pass

