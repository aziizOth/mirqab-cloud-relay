#!/usr/bin/expect -f
# Deploy to VM using expect for password automation

set timeout 300
set host "192.168.100.67"
set user "relay"
set password "relay@123\$"

# First, copy the install script
spawn scp -o StrictHostKeyChecking=no /home/sdx/Projects/mirqab-cloud-relay/deploy/install.sh $user@$host:/tmp/
expect {
    "password:" { send "$password\r"; exp_continue }
    eof
}

# Run install script
spawn ssh -o StrictHostKeyChecking=no $user@$host "sudo bash /tmp/install.sh"
expect {
    "password:" { send "$password\r"; exp_continue }
    eof
}

puts "Install script completed"
