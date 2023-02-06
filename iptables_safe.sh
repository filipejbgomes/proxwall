#!/bin/bash

iptables=/sbin/iptables
#release lock file
rm -rf $(dirname $(readlink -f $0))/iptables.lock

# Reset/Flush chains
$iptables -P INPUT ACCEPT
$iptables -P OUTPUT ACCEPT
$iptables -P FORWARD ACCEPT
$iptables -F
$iptables -t nat -F
$iptables -t mangle -F
$iptables -X

# allow loopback interface
$iptables -A INPUT -i lo -m comment --comment "Allow loopback in" -j ACCEPT
$iptables -A OUTPUT -o lo -m comment --comment "Allow loopback out" -j ACCEPT

# prevent ssh lockout on port 22
$iptables -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT


# allow minimal ICMP types (to enable ping echo (replies))
$iptables -A INPUT -p icmp -m icmp --icmp-type 8 -s 0/0 -m state --state NEW,ESTABLISHED -j ACCEPT
$iptables -A OUTPUT -p icmp -m icmp --icmp-type 0 -d 0/0 -m state --state ESTABLISHED -j ACCEPT

#--- drop all traffic ---#
$iptables -A INPUT -j DROP
$iptables -A OUTPUT -j DROP
$iptables -A FORWARD -j DROP

