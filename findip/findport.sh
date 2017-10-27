#! /bin/bash

Hostname=`hostname`
#Ls=`ls /root/.vnc/$Hostname\:*pid`

Port=`ls /root/.vnc/vm1\:*.pid | awk -F " " '{print $1}' | wc -l`
#Port=$[5900+$Port]

echo $Port
