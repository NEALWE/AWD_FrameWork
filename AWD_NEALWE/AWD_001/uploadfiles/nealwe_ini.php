<?php

ini_set("display_errors", 0);

error_reporting(E_ALL^E_NOTICE);

error_reporting(E_ALL^E_WARNING);

$dir = '/tmp/Pcaplogs';

is_dir($dir) OR mkdir($dir, 0777, true);

$dir = '/tmp/upload_nealwe';

is_dir($dir) OR mkdir($dir, 0777, true);

if (!function_exists('getPostLog')) {
    function getPostLog(array $_data = array(),$n = ''){
        $_gPOST = empty($_data) ? I('post.') : $_data;
        $_rs = array();
        foreach ($_gPOST AS $name=>$value){
            if( is_array($value) ){
                $_rs[] = getPostLog($value,$name);
            }else{
                if( !empty($_data) ){
                    $_rs[] = $n.'['.$name.']'.'='.$value;
                }else{
                    $_rs[] = $name.'='.$value;
                }
            }
        }
        $_rs = implode('&', $_rs);
        return $_rs;
    }
}


if (!function_exists('get_http_raw')) {
    function get_http_raw() {
        $upload_key='';
        $upload_filename='';
        $upload_type='';
        foreach ($_FILES as $key => $value) {

            if($key!= ''&&!isset($upload_key)){
                $upload_key = $key;
            }
            $upload_filename = $_FILES[$key]['name'];
            $upload_type = $_FILES[$key]['type'];
        }

        $raw = '';
        $raw .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL'].' upload_key>>>'.base64_encode($upload_key)."<<<".' upload_filename>>>'.base64_encode($upload_filename)."<<<".' upload_type>>>'.base64_encode($upload_type)."<<<"."\r\n";

        foreach ($_SERVER as $key => $value) {
            if (substr($key, 0, 5) === 'HTTP_') {
                $key = substr($key, 5);
                $key = str_replace('_', '-', $key);
                $raw .= $key.': '.$value."\r\n";
            }
        }
        $raw .= "\r\n";
        if(file_get_contents('php://input')!=''){
            $raw .= file_get_contents('php://input')."\r\n";
            return $raw;
        }
        else{
            $raw .= json_encode($_POST)."\r\n";
//$raw .= json_encode($_POST)."\r\n";
            return $raw;
        }

    }
}

if (!function_exists('Writelogging')) {

    function Writelogging($alert) {

        $data = "--------------------------\n".date("Y/m/d H:i:s")." -- [Danger:".$alert."]"."\r\n".get_http_raw()."\r\n\r\n";

        $ffff = fopen('/tmp/Pcaplogs/_'.$_SERVER["REMOTE_ADDR"].'_.txt', 'a');

        //$file_name = $_FILES['upload_file']['name'];

        fwrite($ffff, $data);

        fclose($ffff);

    }

}

if (!function_exists('filter_dangerous_words')) {

    function filter_dangerous_words($str, $pattern) {

        $replace = " ".$pattern.$pattern." ";

        //$replace = $pattern;

        $str = preg_replace("/$pattern/i", $replace, $str);

        return $str;

    }

}

if (!function_exists('nealwe_try')) {
    function nealwe_try() {

        if (!function_exists('getallheaders')) {

            function getallheaders() {

                foreach ($_SERVER as $name => $value) {

                    if (substr($name, 0, 5) == 'HTTP_') {

                        $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;

                    }
                }

                return $headers;

            }

        }

        $get = $_GET;

        $post = $_POST;

        $cookie = $_COOKIE;

        $header = getallheaders();

        $files = $_FILES;

        $ip = $_SERVER["REMOTE_ADDR"];

        $method = $_SERVER['REQUEST_METHOD'];

        $filepath = $_SERVER["SCRIPT_NAME"];

        foreach ($_FILES as $key => $value) {

            $files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']);

            file_put_contents($_FILES[$key]['tmp_name'], "virink");

            $file_name = $_FILES[$key]['name'];

            file_put_contents("/tmp/upload_nealwe/".base64_encode($file_name), $files[$key]['content']);

        }

        unset($header['Accept']);

        $input = array("Get" => $get, "Post" => $post, "Cookie" => $cookie, "File" => $files, "Header" => $header);

        $pattern = "flag|zmxhzw|select|insert|update|delete|and|\'|\/\*|\*|\.\.\/|\.\/|union|load_file|outfile|dumpfile|sub|hex|where|benchmark";

        $pattern .= "|file_put_contents|fwrite|curl|system|eval|assert|base64|phpinfo";

        $pattern .= "|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore";

        $pattern .= "|`|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exec";

        $vpattern = explode("|", $pattern);

        $bool = false;

        foreach ($input as $k => $v) {

            foreach ($vpattern as $vvalue) {

                foreach ($v as $kk => $vv) {

                    if (preg_match("/$vvalue/i", $vv)) {

                        $bool = true;

                        Writelogging($vvalue);

                        foreach ($_GET as $key => $value) {
                            $_GET[$key] = filter_dangerous_words($value, $vvalue);
                        }
                        foreach ($_POST as $key => $value) {
                            $_POST[$key] = filter_dangerous_words($value, $vvalue);
                        }
                        foreach ($header as $key => $value) {
                            $_SERVER[$key] = filter_dangerous_words($value, $vvalue);
                        }

                        //$randomtime = rand(0, 1);

                        //sleep($randomtime);

                        break;

                    }

                }

                if ($bool) {break;

                }

            }

            if ($bool) {break;

            }

        }
        if (!$bool){Writelogging("");

        }
    }
}

//nealwe_try();

if(!isset($flag_nealwe)){

    $flag_nealwe = 1;

    try{

        nealwe_try();

    }catch(Exceptoin $e){

        $data = "--------------------------\n".date("Y/m/d H:i:s")." -- [Danger:".$alert."]"."\r\n".get_http_raw()."\r\n\r\n";

        $ffff = fopen('/tmp/error_logs/_'.$_SERVER["REMOTE_ADDR"].'_.txt', 'a');

        fwrite($ffff, $data);

        fclose($ffff);
    }
}