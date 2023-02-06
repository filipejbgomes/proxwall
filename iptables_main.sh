#!/bin/bash

#safeguard to be triggered in case main script fails
[[ -f $(dirname $(readlink -f $0))/iptables.lock ]] && { echo "lock file found, script halted <<TODO:add alerting hook>s>" && source $(dirname $(readlink -f $0))/iptables_safe.sh; exit 1;}

# read config file
[[ ! -f $(dirname $(readlink -f $0))/iptables.conf ]] && { echo "Config file not found, exiting!" && touch $(dirname $(readlink -f $0))/iptables.lock}; exit 1;}
source $(dirname $(readlink -f $0))/iptables.conf

#verify only 1 instance runs at a time
[[ $(ps -ef | grep `echo  $(basename "$0")` | grep -v grep | wc -l) -gt 3 ]] && { LogMsg "ERROR" "${BASH_SOURCE[0]} is already running" && exit 0; }; LogMsg "INFO" "Executing";

echo -e "
External IP: $PUB1_ADDR
Cluster address: $LAN1_ADDR
VM's address: $LAN2_ADDR
Cluster subnet: $LAN1_SUB
VM subnet: $LAN2_SUB\n"

echo -e "\nRunning ${BASH_SOURCE[0]}"
[[ -z "$PUB1_ADDR" ]] && { LogMsg "ERROR" "External IP var is empty, cannot proceed!!" && touch $(dirname $(readlink -f $0))/iptables.lock; exit 1; };
[[ ! -d /sys/class/net/${PUB1} ]] && { LogMsg "ERROR" "$PUB Interface is DOWN!" && touch $(dirname $(readlink -f $0))/iptables.lock && exit 1;}; LogMsg "INFO" "Interface $PUB1 is UP";
[[ ! -d /sys/class/net/${LAN1} ]] && { LogMsg "ERROR" "$LAN1 Interface is DOWN!" && clusterlan=0; }; LogMsg "INFO" "Interface $LAN1 is UP" && clusterlan=1;
[[ ! -d /sys/class/net/${LAN2} ]] && { LogMsg "ERROR" "$LAN2 Interface is DOWN!" && vmlan=0; }; LogMsg "INFO" "Interface $LAN2 is UP" && vmlan=1;

# Reset/Flush chains
LogMsg "INFO" "Flushing IPTABLES"
source $(dirname $(readlink -f $0))/iptables_flush.sh

# allow loopback interface
$iptables -A INPUT -i lo -m comment --comment "Allow loopback in" -j ACCEPT
$iptables -A OUTPUT -o lo -m comment --comment "Allow loopback out" -j ACCEPT

# prevent ssh lockout on port 22
LogMsg "INFO" "Prevent ssh lockout"
$iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$iptables -A INPUT -p tcp --dport 22 -j ACCEPT # ssh to host
$iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT # ssh to host
$iptables -A INPUT -p tcp --dport 6969 -j ACCEPT # ssh to host for my setup
$iptables -A OUTPUT -p tcp --dport 6969 -j ACCEPT # ssh to host for my setup

LogMsg "INFO" "Process rate limiting rules"
# rate limit connections & log it
#$iptables -A INPUT -i ${PUB1} -m limit --limit 1000/min -j LOG --log-level 4 --log-prefix 'INPUT:DROP:ipt_ratelimit_in_drop'
#$iptables -A OUTPUT -o ${PUB1} -m limit --limit 6000/hour -j LOG --log-level 4 --log-prefix 'INPUT:DROP:ipt_ratelimit_out_drop'

LogMsg "INFO" "Allow ICMP 0,8 from PUB"
# allow minimal ICMP types (to enable ping echo (replies))
$iptables -A INPUT -p icmp -m icmp --icmp-type 8 -s 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$iptables -A OUTPUT -p icmp -m icmp --icmp-type 0 -s 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$iptables -A INPUT -p icmp -m icmp --icmp-type 0 -s 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$iptables -A OUTPUT -p icmp -m icmp --icmp-type 8 -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# Drop bad packets
$iptables -A INPUT -m state --state INVALID -j LOG --log-level 4 --log-prefix 'INPUT:DROP:ipt_invalid_packet'
$iptables -A INPUT -m state --state INVALID -j DROP
#$iptables -A INPUT -p tcp ! --syn -j DROP # SYN
$iptables -A INPUT -i ${PUB1} -f -j DROP # fragmented
#$iptables -A INPUT -i ${PUB1} -p tcp --tcp-flags ALL ALL -j DROP # XMAS
#$iptables -A INPUT -i ${PUB1} -p tcp --tcp-flags ALL NONE -j DROP # NULL

LogMsg "INFO" "Processing interface rules"
# allow established connections, and the ones not coming from the public interface
$iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT # allow established from all interfaces
#$iptables -A INPUT -m state --state NEW,ESTABLISHED -i ${LAN2} -j ACCEPT # allow from VM subnet
#$iptables -A OUTPUT -m state --state NEW,ESTABLISHED -o ${LAN2} -j ACCEPT # allow from VM subnet
#$iptables -A INPUT -m state --state NEW,ESTABLISHED -i ${LAN1} -j ACCEPT # allow from CLUSTER subnet
$iptables -A OUTPUT -m state --state NEW,ESTABLISHED -s ${LAN1_ADDR} -o ${LAN1} -j ACCEPT # allow from CLUSTER subnet
#$iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT # allow output for established connections on all interfaces
$iptables -A OUTPUT -o ${PUB1} -m state --state ESTABLISHED -j ACCEPT # allow output for established connections on all interfaces to public interface

# OUTPUT port rules so the Proxmox HOST can access web for updates, etc (port 53 for external dns resolution)
$iptables -A OUTPUT -o ${PUB1} -p tcp --dport 80 -m state --state NEW -j ACCEPT #host acess to web
$iptables -A OUTPUT -o ${PUB1} -p tcp --dport 443 -m state --state NEW -j ACCEPT #host acess to secure web
$iptables -A OUTPUT -o ${PUB1} -p udp --dport 53 -m state --state NEW -j ACCEPT #host acess to dns

#--- create new chain to log dropped packet---#
$iptables -N INPUT_LOGDROP
$iptables -N OUTPUT_LOGDROP
$iptables -N FORWARD_LOGDROP

#--- Run external script for STATIC WHITELIST adresses ---#
source $(dirname $(readlink -f $0))/iptables_static.sh

#--- Run external script for DYNAMIC WHITELIST adresses ---#
source $(dirname $(readlink -f $0))/iptables_dynamic.sh

# explicitly deny input from any other networks to the private lan on this host
#$iptables -A INPUT -m state --state NEW ! -s ${LAN2_SUB} -d ${LAN2_SUB} -j DROP

#enable multicast on interface lan1 (needed for clustering if not using tinc)
$iptables -A INPUT -i ${LAN1} -m pkttype --pkt-type multicast -j ACCEPT
$iptables -A OUTPUT -o ${LAN1} -m pkttype --pkt-type multicast -j ACCEPT

#Open cluster ports on cluster lan. Corosync port 5404 and 5405
$iptables -A INPUT -i ${LAN1} -p udp --dport 5404 -m state --state NEW -j ACCEPT
$iptables -A INPUT -i ${LAN1} -p udp --dport 5405 -m state --state NEW -j ACCEPT
$iptables -A OUTPUT -o ${LAN1} -p udp --dport 5404 -j ACCEPT
$iptables -A OUTPUT -o ${LAN1} -p udp --dport 5405 -j ACCEPT

#alternative rules for multicast
#iptables -A INPUT   -s 224.0.0.0/4 -j ACCEPT
#iptables -A FORWARD -s 224.0.0.0/4 -d 224.0.0.0/4 -j ACCEPT
#iptables -A OUTPUT  -d 224.0.0.0/4 -j ACCEPT

# enable NAT on public interface (ex: so VM's can acces the web)
$iptables -t nat -A POSTROUTING -o ${PUB1} -j MASQUERADE

# TO-DO:create a ip_NAT to handle nat rules from public subnet to internal VM subnet to access services without passing through VPN

##------------------------------------------------------##
### SSH

#--- Run external script with ssh port forwarding ---#
[[ vmlan -eq '0' ]] && { LogMsg "ERROR" "Interface not available"; }; LogMsg "INFO" "Loading VM SSH forwarding rules" && source $(dirname $(readlink -f $0))/iptables_ssh_forwarding.sh;

##------------------------------------------------------##
### Services

#--- Run external script with ssh port forwarding ---#
[[ vmlan -eq '0' ]] && { LogMsg "ERROR" "Interface not available"; }; LogMsg "INFO" "Loading VM port forwarding rules" && source $(dirname $(readlink -f $0))/iptables_port_forwarding.sh;


#--- LAST STATEMENTS! DO NOT INSERT ANYTHING BELOW THIS LINE! ---#

#--- drop all traffic that doesnt not fit on a rule and log it  ---#
$iptables -A INPUT -j INPUT_LOGDROP
$iptables -A OUTPUT -j OUTPUT_LOGDROP
$iptables -A FORWARD -j FORWARD_LOGDROP

$iptables -A INPUT_LOGDROP -j LOG --log-prefix "INPUT:DROP: " --log-level 4
$iptables -A OUTPUT_LOGDROP -j LOG --log-prefix "OUTPUT:DROP: " --log-level 4
$iptables -A FORWARD_LOGDROP -j LOG --log-prefix "FORWARD:DROP: " --log-level 4

$iptables -A INPUT_LOGDROP -j DROP
$iptables -A OUTPUT_LOGDROP -j DROP
$iptables -A FORWARD_LOGDROP -j DROP

#release lock file
LogMsg "INFO" "release lock file: $(dirname $(readlink -f $0))/iptables.lock"
rm -rf $(dirname $(readlink -f $0))/iptables.lock
#--- end script ---#
