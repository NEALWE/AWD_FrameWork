<?php
$a = $_GET['a'];

$b = file_get_contents("/tmp/f625597d2ec.log");
if(md5(md5($a)) === '8444735358bb65f625597d2ec39745bd'){
    echo $b;
}