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
send "ps aux | grep '${listen_port}' | grep -v grep | awk '{print \$2}' | xargs kill -9\r"
expect -re ".*\[\$#\]"
send "exit\r"

spawn ps aux | grep "autossh -M ${listen_port}" | grep -v grep | awk '{print $2}' | xargs kill -9