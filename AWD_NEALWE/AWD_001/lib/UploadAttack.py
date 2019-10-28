# coding:utf-8

# 作者：nealwe
# 时间：2018/5/24
# 需要实现的功能有 '输入上传URL' -> '自动上传所有文件并验证是否存活' -> '如果存活则写入文件'

import os
import paramiko
import requests
import random

class UploadAttack():
    def __init__(self):
        UserAgent = self.ChooseUserAgent()

    def ChooseUserAgent(self):
        UserAgent = random.choice([
            # pc端
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
            "Mozilla/5.0(compatible;MSIE9.0;WindowsNT6.1;Trident/5.0;",
            "Mozilla/4.0(compatible;MSIE7.0;WindowsNT5.1;360SE)",
            # 移动端
            "Mozilla/5.0(iPhone;U;CPUiPhoneOS4_3_3likeMacOSX;en-us)AppleWebKit/533.17.9(KHTML,likeGecko)Version/5.0.2Mobile/8J2Safari/6533.18.5",
            "Mozilla/5.0(iPod;U;CPUiPhoneOS4_3_3likeMacOSX;en-us)AppleWebKit/533.17.9(KHTML,likeGecko)Version/5.0.2Mobile/8J2Safari/6533.18.5"
        ])
        return UserAgent

    # >>> url = 'http://httpbin.org/post'
    # >>> multiple_files = [
    #    ('images', ('foo.png', open('foo.png', 'rb'), 'image/png')),
    #    ('images', ('bar.png', open('bar.png', 'rb'), 'image/png'))]
    # >>> r = requests.post(url, files=multiple_files)
    # >>> r.text
    # {
    #     ...
    # 'files': {'images': 'data:image/png;base64,iVBORw ....'}
    # 'Content-Type': 'multformipart/-data; boundary=3131623adb2043caaeb5538cc7aa0b3a',
    #                 ...
    # }
    def SendFiles(self,folder):
        # folder 为需要上传文件的文件夹路径
        pass