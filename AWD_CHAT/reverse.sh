# !/usr/bin/expect -f
# set ip [ lindex $argv 0 ]
# set port [ lindex $argv 1 ]
# set username [ lindex $argv 2 ]

set user1 [ lindex $argv 0 ]
set pass1 [ lindex $argv 1 ]
set ip1 [ lindex $argv 2 ]
set listen_port [ lindex $argv 3 ]
set tmp_port [ lindex $argv 4 ]
set monitor_port [ lindex $argv 5 ]

set timeout 6

spawn ssh ${user1}@${ip1}
expect {
    "*yes/no" { send "yes\r" exp_continue}
    "*password:" { send "${pass1}\r" }
}

expect -re ".*\[\$#\]"
send "ssh -CNfgL ${listen_port}:localhost:${tmp_port} ${user1}@localhost\r"
expect {
    "*yes/no" { send "yes\r";exp_continue }
    "*password:" { send "${pass1}\r" }
}
expect -re ".*\[\$#\]"
send "exit\r"

spawn autossh -M ${monitor_port} -qngNTR ${tmp_port}:localhost:${listen_port} ${user1}@${ip1}
expect {
    "*yes/no" {send "yes\r";exp_continue}
    "*password" {send "${pass1}\r";exp_continue}
}

expect eof