#coding:utf-8
from flask import Flask, request
import sqlite3
import logging

app = Flask(__name__)


@app.route('/<flag>/<csrf>/')
def index(csrf,flag):
    flag=flag[1:]
    print(flag)
    #print request.headers
    #print request.form
    # print request.form.get('flag')
    # print 'ASD'
    # print request.form.get('csrf_token')
    local_file_path = '/home/nealwe/Desktop/nealwe/AWD-share/AWD/AWD_001/ReserveShellManager/'
    conn = sqlite3.connect('{}shell.sqlite'.format(local_file_path))
    cur = conn.cursor()

    try:
        sql1 = """UPDATE "main"."csrf_flag" SET "flag" = \"%s\" WHERE  "csrf" = \"%s\"""" % (flag, csrf)
        cur.execute(sql1)
    except:
        print("flag unique")
    try:
        sql2 = """UPDATE "main"."csrf_flag" SET "csrf" = NULL WHERE  "csrf" = \"%s\"""" % (csrf)
        cur.execute(sql2)
    except:
        print("csrf set null error")
    conn.commit()
    conn.close()
    return 'ok'

def InsertData(sql):
    conn = None
    try:
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
    except Exception as e:
        print(sql)

'''def CheckExit(table, title):
        sql = 'select * from {0} where csrf= \'{1}\' '.format(table, title)
        num = ""
        try:
            conn = sqlite3.connect("csrf_flag")
            cur = conn.cursor()
            cur.execute(sql)
            conn.commit()
            num = cur.fetchall()
            conn.close()
            try:
                n = len(num)
            except:
                n = 0
        except Exception as e:
            logging.debug(traceback.format_exc())
        finally:
            if hasattr(conn, 'close'):
                conn.close()
            if n == 0:
                return False
            else:
                return True'''


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=3004, debug=True)





