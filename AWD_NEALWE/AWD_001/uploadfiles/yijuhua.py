#coding: utf-8

import os,sys
import re
import hashlib
import time

rulelist = [
    '(\$_(GET|POST|REQUEST)\[.{0,15}\]\s{0,10}\(\s{0,10}\$_(GET|POST|REQUEST)\[.{0,15}\]\))',
    '((eval|assert)(\s|\n)*\((\s|\n)*\$_(POST|GET|REQUEST)\[.{0,15}\]\))',
    '(eval(\s|\n)*\(base64_decode(\s|\n)*\((.|\n){1,200})',
    '(function\_exists\s*\(\s*[\'|\"](popen|exec|proc\_open|passthru)+[\'|\"]\s*\))',
    '((exec|shell\_exec|passthru)+\s*\(\s*\$\_(\w+)\[(.*)\]\s*\))',
    '(\$(\w+)\s*\(\s.chr\(\d+\)\))',
    '(\$(\w+)\s*\$\{(.*)\})',
    '(\$(\w+)\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\s*\))',
    '(\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\(\s*\$(.*)\))',
    '(\$\_\=(.*)\$\_)',
    '(\$(.*)\s*\((.*)\/e(.*)\,\s*\$\_(.*)\,(.*)\))',
    '(new com\s*\(\s*[\'|\"]shell(.*)[\'|\"]\s*\))',
    '(echo\s*curl\_exec\s*\(\s*\$(\w+)\s*\))',
    '((fopen|fwrite|fputs|file\_put\_contents)+\s*\((.*)\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\](.*)\))',
    '(\(\s*\$\_FILES\[(.*)\]\[(.*)\]\s*\,\s*\$\_(GET|POST|REQUEST|FILES)+\[(.*)\]\[(.*)\]\s*\))',
    '(\$\_(\w+)(.*)(eval|assert|include|require|include\_once|require\_once)+\s*\(\s*\$(\w+)\s*\))',
    '((include|require|include\_once|require\_once)+\s*\(\s*[\'|\"](\w+)\.(jpg|gif|ico|bmp|png|txt|zip|rar|htm|css|js)+[\'|\"]\s*\))',
    '(eval\s*\(\s*\(\s*\$\$(\w+))',
    '((eval|assert|include|require|include\_once|require\_once|array\_map|array\_walk)+\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)+\[(.*)\]\s*\))',
    '(preg\_replace\s*\((.*)\(base64\_decode\(\$)'
    ]

def scan(path):
    print('           可疑文件         ')
    print('*'*30)
    for root,dirs,files in os.walk(path):
        for filespath in files:
            if os.path.getsize(os.path.join(root,filespath))<1024000:
                file= open(os.path.join(root,filespath))
                filestr = file.read()
                file.close()
                for rule in rulelist:
                    result = re.compile(rule).findall(filestr)
                    if result:
                        print '文件:'+os.path.join(root,filespath )
                        print '恶意代码:'+str(result[0][0:200])
                        print ('最后修改时间:'+time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.path.getmtime(os.path.join(root,filespath)))))
                        print '\n\n'
                        break

def md5sum(md5_file):
    m = hashlib.md5()
    fp = open(md5_file)
    m.update(fp.read())
    fp.close()
    return m.hexdigest()


# if md5sum('/etc/issue') == '3e3c7c4194b12af573ab11c16990c477':
#     if md5sum('/usr/sbin/sshd') == 'abf7a90c36705ef679298a44af80b10b':
#         pass
#     else:
#         print('*'*40)
#         print "\033[31m sshd被修改，疑似留有后门\033[m"
#         print('*'*40)
#         time.sleep(5)
# if md5sum('/etc/issue') == '6c9222ee501323045d85545853ebea55':
#     if md5sum('/usr/sbin/sshd') == '4bbf2b12d6b7f234fa01b23dc9822838':
#         pass
#     else:
#         print('*'*40)
#         print "\033[31m sshd被修改，疑似留有后门\033[m"
#         print('*'*40)
#         time.sleep(5)



if __name__=='__main__':

    # if len(sys.argv)!=2:
    #     print '参数错误'
    #     print "\t按恶意代码查找:"+sys.argv[0]+'目录名'
    # if os.path.lexists(sys.argv[1]) == False:
    #     print "目录不存在"
    #     exit()
    print ('\n\n开始查找:'+sys.argv[1])
    if len(sys.argv) ==2:
        scan(sys.argv[1])
    else:
        exit()