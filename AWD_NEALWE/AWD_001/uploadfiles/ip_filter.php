<?php
ini_set("display_errors", 0);

error_reporting(E_ALL ^ E_NOTICE);

error_reporting(E_ALL ^ E_WARNING);
/*
 *通过禁止IP频繁访问防止网站被防攻击代码
 *design by www.scutephp.com
 */





header('Content-type: text/html; charset=utf-8');

$ip           = $_SERVER['REMOTE_ADDR'];//获取当前访问者的ip
$logFilePath  = '/tmp/logs/ip_log/';//日志记录文件保存目录
$fileht       = '/tmp/logs/.htaccess2';//被禁止的ip记录文件
$allowtime    = 5;//防刷新时间
$allownum     = 30;//防刷新次数
$allowRefresh = 1200000000;//在允许刷新次数之后加入禁止ip文件中

if (!file_exists($fileht)) {
	file_put_contents($fileht, '');
}
$filehtarr = @file($fileht);
if (in_array($ip."\r\n", $filehtarr)) {
	exit('警告：你是访问了多少次了？现在你的IP已经被禁止了，告辞！');
}
//加入禁止ip
$time       = time();
$fileforbid = $logFilePath.'forbidchk.dat';
if (file_exists($fileforbid)) {
	if ($time-filemtime($fileforbid) > 30) {
		@unlink($fileforbid);
	} else {
		$fileforbidarr = @file($fileforbid);
		if ($ip == substr($fileforbidarr[0], 0, strlen($ip))) {
			if ($time-substr($fileforbidarr[1], 0, strlen($time)) > 120) {
				@unlink($fileforbid);
			} else if ($fileforbidarr[2] > $allowRefresh) {
				file_put_contents($fileht, $ip."\r\n", FILE_APPEND);
				@unlink($fileforbid);
			} else {
				$fileforbidarr[2]++;
				file_put_contents($fileforbid, $fileforbidarr);
			}
		}
	}
}
//防刷新
$str  = '';
$file = $logFilePath.'ipdate.dat';
if (!file_exists($logFilePath) && !is_dir($logFilePath)) {
	mkdir($logFilePath, 0777);
}
if (!file_exists($file)) {
	file_put_contents($file, '');
}
$uri      = $_SERVER['REQUEST_URI'];//获取当前访问的网页文件地址
$checkip  = md5($ip);
$checkuri = md5($uri);
$yesno    = true;
$ipdate   = @file($file);
foreach ($ipdate as $k => $v) {
	$iptem   = substr($v, 0, 32);
	$uritem  = substr($v, 32, 32);
	$timetem = substr($v, 64, 10);
	$numtem  = substr($v, 74);
	if ($time-$timetem < $allowtime) {
		if ($iptem != $checkip) {
			$str .= $v;
		} else {
			$yesno = false;
			if ($uritem != $checkuri) {
				$str .= $iptem.$checkuri.$time."\r\n";
			} else if ($numtem < $allownum) {
				$str .= $iptem.$uritem.$timetem.($numtem+1)."\r\n";
			} else {
				if (!file_exists($fileforbid)) {
					$addforbidarr = array($ip."\r\n", time()."\r\n", 1);
					file_put_contents($fileforbid, $addforbidarr);
				}
				$tmp666 = rand(5, 10);
				//echo "sleep:".$tmp666 ;
				sleep($tmp666);
				@file_put_contents($logFilePath.'forbided_ip.log', $ip.'--'.date('Y-m-d H:i:s', time()).'--'.$uri."\r\n", FILE_APPEND);
				$timepass = $timetem+$allowtime-$time;

				exit('警告：访问太快！');
			}
		}
	}
}
if ($yesno) {
	$str .= $checkip.$checkuri.$time."\r\n";
}
file_put_contents($file, $str);