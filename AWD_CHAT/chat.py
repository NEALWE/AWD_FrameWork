from flask import Flask, jsonify, request, redirect, url_for, render_template, render_template_string, make_response
import collections
import time
import requests
from Crypto.Cipher import AES
import base64
import sqlite3
from nealwe_web_lib import *
import re
from flask_cors import CORS
from config import *

# app = Flask(__name__)
app = Flask(__name__,template_folder = "./dist",static_folder = "./static",static_url_path='')
CORS(app, supports_credentials=True)

@app.after_request
def af_request(resp):     
    """
    #请求钩子，在所有的请求发生后执行，加入headers。
    :param resp:
    :return:
    """
    resp = make_response(resp)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'x-requested-with,content-type'
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp

# Flag = collections.namedtuple("Flag", ["ip", "data", "time"])
Flag = collections.namedtuple("Flag", ['data'])
recvs = []
sends = []

flag_path = "flag.txt"

key = "JsPI...Nealwe"
ips = "172.17.68.200-210"
port = 15001
tmp_port = 25001
tmp_monitor = 35001
correct_token = "Nealwe_test_wechat"


def module_path():
    """
    This will get us the program's directory
    """
    return os.path.dirname(os.path.realpath(__file__))


def kill_port(user, passwd, ip_remote, listen_port, tmp_port, tmp_monitor):
    print("[+]{} {}: {}".format(ip_remote, listen_port, tmp_port))
    bash_path = os.path.join(module_path(), "reverse_kill.sh")
    b = os.popen(f"expect -f {bash_path} {user} {passwd} {ip_remote} {listen_port} {tmp_port} {tmp_monitor}")
    # b = os.popen(f"expect -f {bash_path} {user} {passwd} {ip} {listen_port} {tmp_port}")
    print(b.read())


def open_port(user, passwd, ip_remote, listen_port, tmp_port, tmp_monitor):
    print("[+]{} {}: {}".format(ip_remote, listen_port, tmp_port))
    bash_path = os.path.join(module_path(), "reverse.sh")
    b = os.popen(f"expect -f {bash_path} {user} {passwd} {ip_remote} {listen_port} {tmp_port} {tmp_monitor}")
    # b = os.popen(f"expect -f {bash_path} {user} {passwd} {ip} {listen_port} {tmp_port}")
    print(b.read())







CRAETE_TABLE_SQL_ip_flag = 'CREATE TABLE if not exists  ip_flag ("id" INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE , "ip" VARCHAR UNIQUE , "flag" VARCHAR UNIQUE );'
CRAETE_TABLE_SQL_ip_message = 'CREATE TABLE if not exists  ip_message ("id" INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE , "ip" VARCHAR , "message" VARCHAR );'
INSERT_DATA = """INSERT INTO ip_flag ("ip","flag") VALUES ('{0}', '{1}');"""
UPDATA_DATA = """UPDATE ip_flag SET "flag" ='{1}' where "ip" = '{0}'"""


def initSqlite():
    local_file_path = module_path()
    conn = sqlite3.connect(os.path.join(local_file_path, "flag.sqlite"))
    print(os.path.join(local_file_path, "flag.sqlite"))
    try:
        conn.execute(CRAETE_TABLE_SQL_ip_flag)
    except Exception as e:
        print(e)
    try:
        conn.execute(CRAETE_TABLE_SQL_ip_message)
    except Exception as e:
        print(e)


import queue
import threading
import contextlib
import time

# 创建空对象,用于停止线程
StopEvent = object()


def callback(status, result):
    """
    根据需要进行的回调函数，默认不执行。
    :param status: action函数的执行状态
    :param result: action函数的返回值
    :return:
    """
    pass


def action(thread_name, arg):
    """
    真实的任务定义在这个函数里
    :param thread_name: 执行该方法的线程名
    :param arg: 该函数需要的参数
    :return:
    """
    # 模拟该函数执行了0.1秒
    time.sleep(0.1)
    print("第%s个任务调用了线程 %s，并打印了这条信息！" % (arg + 1, thread_name))


class ThreadPool:
    def __init__(self, max_num, max_task_num=None):
        """
        初始化线程池
        :param max_num: 线程池最大线程数量
        :param max_task_num: 任务队列长度
        """
        # 如果提供了最大任务数的参数，则将队列的最大元素个数设置为这个值。
        if max_task_num:
            self.q = queue.Queue(max_task_num)
        # 默认队列可接受无限多个的任务
        else:
            self.q = queue.Queue()
        # 设置线程池最多可实例化的线程数
        self.max_num = max_num
        # 任务取消标识
        self.cancel = False
        # 任务中断标识
        self.terminal = False
        # 已实例化的线程列表
        self.generate_list = []
        # 处于空闲状态的线程列表
        self.free_list = []

    def put(self, func, args, callback=None):
        """
        往任务队列里放入一个任务
        :param func: 任务函数
        :param args: 任务函数所需参数
        :param callback: 任务执行失败或成功后执行的回调函数，回调函数有两个参数
        1、任务函数执行状态；2、任务函数返回值（默认为None，即：不执行回调函数）
        :return: 如果线程池已经终止，则返回True否则None
        """
        # 先判断标识，看看任务是否取消了
        if self.cancel:
            return
        # 如果没有空闲的线程，并且已创建的线程的数量小于预定义的最大线程数，则创建新线程。
        if len(self.free_list) == 0 and len(self.generate_list) < self.max_num:
            self.generate_thread()
        # 构造任务参数元组，分别是调用的函数，该函数的参数，回调函数。
        w = (func, args, callback,)
        # 将任务放入队列
        self.q.put(w)

    def generate_thread(self):
        """
        创建一个线程
        """
        # 每个线程都执行call方法
        t = threading.Thread(target=self.call)
        t.start()

    def call(self):
        """
        循环去获取任务函数并执行任务函数。在正常情况下，每个线程都保存生存状态，
        直到获取线程终止的flag。
        """
        # 获取当前线程的名字
        current_thread = threading.currentThread().getName()
        # 将当前线程的名字加入已实例化的线程列表中
        self.generate_list.append(current_thread)
        # 从任务队列中获取一个任务
        event = self.q.get()
        # 让获取的任务不是终止线程的标识对象时
        while event != StopEvent:
            # 解析任务中封装的三个参数
            func, arguments, callback = event
            # 抓取异常，防止线程因为异常退出
            try:
                # 正常执行任务函数
                result = func(current_thread, *arguments)
                success = True
            except Exception as e:
                # 当任务执行过程中弹出异常
                result = None
                success = False
            # 如果有指定的回调函数
            if callback is not None:
                # 执行回调函数，并抓取异常
                try:
                    callback(success, result)
                except Exception as e:
                    pass
            # 当某个线程正常执行完一个任务时，先执行worker_state方法
            with self.worker_state(self.free_list, current_thread):
                # 如果强制关闭线程的flag开启，则传入一个StopEvent元素
                if self.terminal:
                    event = StopEvent
                # 否则获取一个正常的任务，并回调worker_state方法的yield语句
                else:
                    # 从这里开始又是一个正常的任务循环
                    event = self.q.get()
        else:
            # 一旦发现任务是个终止线程的标识元素，将线程从已创建线程列表中删除
            self.generate_list.remove(current_thread)

    def close(self):
        """
        执行完所有的任务后，让所有线程都停止的方法
        """
        # 设置flag
        self.cancel = True
        # 计算已创建线程列表中线程的个数，然后往任务队列里推送相同数量的终止线程的标识元素
        full_size = len(self.generate_list)
        while full_size:
            self.q.put(StopEvent)
            full_size -= 1

    def terminate(self):
        """
        在任务执行过程中，终止线程，提前退出。
        """
        self.terminal = True
        # 强制性的停止线程
        while self.generate_list:
            self.q.put(StopEvent)

    # 该装饰器用于上下文管理
    @contextlib.contextmanager
    def worker_state(self, state_list, worker_thread):
        """
        用于记录空闲的线程，或从空闲列表中取出线程处理任务
        """
        # 将当前线程，添加到空闲线程列表中
        state_list.append(worker_thread)
        # 捕获异常
        try:
            # 在此等待
            yield
        finally:
            # 将线程从空闲列表中移除
            state_list.remove(worker_thread)


def time_format():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def add_to_16(text):
    while len(text) % 16 != 0:
        text += '\0'
    return text.encode()


def aes_encrypt(s):
    s = base64.b64encode(s.encode('utf8')).decode()
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    encrypted_text = aes.encrypt(add_to_16(s))
    encrypted_text = base64.b64encode(encrypted_text)
    return encrypted_text.decode()


def aes_decrypt(s):
    s = base64.b64decode(s)
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    text_decrypted = aes.decrypt(s)
    text = text_decrypted.rstrip(b'\0').decode()
    return base64.b64decode(text).decode()


def ip_list(x):
    ip_list_all = []
    ip_list_tmp = x.split('.')
    if '-' in x:
        for i in ip_list_tmp:
            d = i
            if '-' in d:
                p = ip_list_tmp.index(d)
                l = d.split('-')
                m = int(l[0])
                n = int(l[1])
        for j in range(m, n + 1):
            ip_list_tmp[p] = str(j)
            ip = '.'.join(ip_list_tmp)
            ip_list_all.append(ip)
        # ip_list_tmp = sorted(set(ip_list_all), key=ip_list_all.index)  # 去重
    else:
        ip = '.'.join(ip_list_tmp)
        ip_list_all.append(ip)
        ip_list_all = sorted(set(ip_list_all), key=ip_list_all.index)
    return ip_list_all


def get_recv(text):
    with open(flag_path, "a") as f:
        f.write(text + "\n")
        recv_list = f.readlines()
    return recv_list


def send_flag(thread_name, i, port, ip, flag, token):
    ip = aes_encrypt(ip)
    flag = aes_encrypt(flag)
    url = "http://{}:{}/fuzz".format(i, port)
    params = {
        "token": token,
        'test0': ip,
        'test1': flag
    }
    try:
        requests.post(url=url, data=params, timeout=3)
    except Exception as e:
        pass
    return 0

def send_msg(thread_name, i, port, message):
    url = "http://{}:{}/chat_add".format(i, port)
    print(url)
    params = {
        'test0': message
    }
    # print(url)
    # print(params)
    try:
        requests.post(url=url, data=params, timeout=3)
    except Exception as e:
        pass
    return 0



@app.route('/init', methods=['POST', 'GET'])
def init():
    ip = request.remote_addr
    if ip != "127.0.0.1":
        return "fuck off"
    initSqlite()
    kill_port(user, passwd, ip_remote, port, tmp_port, tmp_monitor)
    open_port(user, passwd, ip_remote, port, tmp_port, tmp_monitor)
    return 'ok'

@app.route('/index', methods=['POST', 'GET'])
def index():
    ip = request.remote_addr
    if ip != "127.0.0.1":
        return "fuck off"
    return render_template("index.html")


@app.route('/chat', methods=['POST', 'GET'])
def chat():
    ip = request.remote_addr
    if ip != "127.0.0.1":
        return "fuck off"
    return render_template("chat.html")


@app.route('/send_bbb', methods=['POST'])
def chat_send():
    data = json.loads(str(request.data, encoding = "utf8"))
    message = aes_encrypt(data['test0'])
    from multiprocessing import Process
    p2 = Process(target=run_send_msg, args=(message,))
    p2.start()
    return 'ok'


@app.route('/chat_add', methods=['POST'])
def chat_add():
    ip = request.remote_addr
    message = request.form['test0']
    try:
        message = byte_to_str(base64.b64encode(aes_decrypt(message).encode("utf-8")))
    except:
        return 'ok!'
    INSERT_DATA = """INSERT INTO ip_message ("ip","message") VALUES ('{0}', '{1}');"""
    local_file_path = module_path()
    conn = sqlite3.connect(os.path.join(local_file_path, "flag.sqlite"))
    try:
        conn.execute(INSERT_DATA.format(ip, message))
        conn.commit()
        print('ok')
    except:
        print('ok!')
    return 'ok'


@app.route('/chat_get', methods=['POST'])
def chat_get():
    import base64
    # id = request.form['id']
    data = json.loads(str(request.data, encoding = "utf8"))
    id = data['id']
    messages = list()
    GET_DATA = f"select id, message from ip_message WHERE id > {id} "
    # GET_DATA = "select id, message from ip_message WHERE id=1"
    local_file_path = module_path()
    conn = sqlite3.connect(os.path.join(local_file_path, "flag.sqlite"))
    c = conn.cursor()
    try:
        cursor = c.execute(GET_DATA)
        conn.commit()
        for row in cursor:
            info = {}
            info['id'] = row[0]
            info['content'] = byte_to_str(base64.b64decode(row[1]))
            messages.append(info)
            # tmp_row = list()
            # tmp_row.append(row[0])
            # tmp_row.append(byte_to_str(base64.b64decode(row[1])))
            # print(tmp_row)
            # messages.append(tmp_row)

    except Exception as e:
        print(e)
    # return render_template("chat_get.html", messages=messages)
    # messages = {'dsad':'dasd'}
    return json.dumps(messages[::-1])


@app.route('/send', methods=['POST', 'GET'])
def send():
    return render_template("send.html")


@app.route('/send_aaa', methods=['POST'])
def flag():
    ip = request.form.get("test0")
    flag = request.form.get("test1")
    token = request.form.get("token")
    if token == correct_token:
        pass
    else:
        return 'ok!'
    from multiprocessing import Process
    p = Process(target=run, args=(port, ip, flag, token,))
    p.start()
    return 'ok'


def run(port, ip, flag, token):
    # 创建一个最多包含5个线程的线程池
    pool = ThreadPool(100)
    # 创建100个任务，让线程池进行处理
    for i in ip_list(ips):
        pool.put(send_flag, (i, port, ip, flag, token,), callback)
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
    return 0


def run_send_msg(message):
    # 创建一个最多包含5个线程的线程池
    pool = ThreadPool(100)
    # 创建100个任务，让线程池进行处理
    for i in ip_list(ips):
        pool.put(send_msg, (i, port, message,), callback)
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
    return 0

def check_ip(ipAddr):
  compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
  if compile_ip.match(ipAddr):
    return True
  else:
    return False

def check_flag(flag):
  try:
      if re.findall(r"([a-zA-Z0-9+/={}]{%s})" % str(len(flag)), flag)[0]:
          return True
      else:
          return False
  except:
    return False

@app.route('/fuzz', methods=['POST', 'GET'])
def recv():
    print(request.form['token'])
    if request.form['token'] == correct_token:
        ip = aes_decrypt(request.form["test0"])
        flag = aes_decrypt(request.form["test1"])
        if check_ip(ip) and check_flag(flag):
            pass
        else:
            return 'ok!'
        INSERT_DATA = """INSERT INTO ip_flag ("ip","flag") VALUES ('{0}', '{1}');"""
        UPDATA_DATA = """UPDATE ip_flag SET "flag" ='{1}' where "ip" = '{0}'"""
        local_file_path = module_path()
        conn = sqlite3.connect(os.path.join(local_file_path, "flag.sqlite"))
        try:
            conn.execute(INSERT_DATA.format(ip, flag))
            conn.commit()
            print('ok')
        except Exception as e:
            print(e)
        try:
            conn.execute(UPDATA_DATA.format(ip, flag))
            conn.commit()
            print('ok')
        except Exception as e:
            print(e)
        conn.close()
        return 'ok'
    else:
        return 'ok!'

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=port, debug=False)
