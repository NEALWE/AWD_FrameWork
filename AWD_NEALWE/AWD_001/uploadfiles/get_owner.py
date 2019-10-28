# coding:utf-8
import os
import pwd
import sys

def get_owner(filename):
    stat = os.lstat(filename)
    uid = stat.st_uid
    pw = pwd.getpwuid(uid)
    return pw.pw_name

print(get_owner(sys.argv[1]))