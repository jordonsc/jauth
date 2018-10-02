#!/bin/bash

app=`python -c "import os; print(os.path.dirname(os.path.realpath(\"$0\")))"`

shopt -s expand_aliases

USERNAME=`cat /var/local/ob/usr`
PASSWORD=`cat /var/local/ob/pw`
GA_HASH=`cat /var/local/ob/ga`
GA_CODE=`${app}/jauth.py "${GA_HASH}"`

expect << EOF
    set timeout 30

    spawn /sbin/vpn up;

    expect "Enter Auth Username: ";
    send "$USERNAME\n";

    expect "Enter Auth Password: ";
    send "$PASSWORD\n";

    expect "CHALLENGE: Enter Google Authenticator Code";
    send "$GA_CODE\n"

    expect eof
EOF
