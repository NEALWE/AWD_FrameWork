# !/usr/bin/expect -f
set ip [ lindex $argv 0 ]
set port [ lindex $argv 1 ]
set user1 [ lindex $argv 2 ]
set pass1 [ lindex $argv 3 ]
set pass2 [ lindex $argv 4 ]


set timeout 6

spawn ssh ${user1}@${ip} -p${port}

expect {
    "*refused" {send "exit\r";}
    "*service not known" { send "exit\r";}
    "*yes/no" { send "yes\r";exp_continue}
    "*password:" {send "${pass1}\r";exp_continue}

}

expect -re ".*\[\$#\]"
send "passwd\r"
expect {
    "*current" { send "${pass1}\r";exp_continue }
    "Enter new UNIX password" { send "${pass2}\r";exp_continue }
    "New password" { send "${pass2}\r";exp_continue }
    "Retype" { send "${pass2}\r"; }
}

expect -re ".*\[\$#\]"

send "killall -u ${user1}\r"