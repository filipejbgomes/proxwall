#!/bin/bash

echo -e "\nRunning ${BASH_SOURCE[0]}"
#initialize vars
   source $(dirname $(readlink -f $0))/iptables.conf
   count_processed=0
   count_port=0
   count_ip=0

#parse source file
   trustedarraycsv=$(dirname $(readlink -f $0))/$rulespath/$vmrulescsv
   sed -i '/^\s*$/d' $trustedarraycsv
   sed -e '/^[[:space:]]*#/d' $trustedarraycsv > $trustedarraycsv".tmp"
   LogMsg "INFO" "Parsing File: $trustedarraycsv"
   IFS=$'\n'
   while read line ; do
       protocol=$(awk -F" " '{print $1}' <<<"$line")
       TrustedHost=$(echo ${line} |awk -F" " '{print $2}' |  cut -d ':' -f 1|awk '{ sub(/^[ \t]+/, ""); print }')
       host_desc=$(awk -F"#" '{print $2}' <<<"$line")

#--- read comma-separated port list from current rule into separate array---#
# input syntax:"tcp 123.123.123.123:80,22,443# description"
      TrustedPorts=()
      IFS=$',' read -r -a TrustedPorts <<<$(echo ${line} |awk -F":" '{print $2}' |  cut -d '#' -f 1|sed 's/[^0-9,]*//g')
      IFS=$'\n'

	for TrustedPort in ${TrustedPorts[@]}; do
#         LogMsg "DEBUG"  "Computed port is: "--$TrustedPort--""
    	    LogMsg "INFO"  "Processing port $TrustedPort for address $TrustedHost"
		$iptables -A PREROUTING -t nat -i ${PUB1} -p tcp --dport $TrustedPort -j DNAT --to $TrustedHost:$TrustedPort
		$iptables -A INPUT -p tcp -m state --state NEW --dport $TrustedPort -i ${PUB1} -j ACCEPT
		$iptables -A OUTPUT -o ${PUB1} -p tcp --sport $TrustedPort -m state --state ESTABLISHED -j ACCEPT
		$iptables -A FORWARD -p tcp -i ${PUB1} -d $TrustedHost --dport $TrustedPort -j ACCEPT
       	    LogMsg "INFO" "IP: $TrustedIP FORWARDING rule added for $TrustedHost -> "$host_desc" <-"
done
let count_processed++
done < $trustedarraycsv".tmp"
#echo "" > $trustedarraycsv".tmp"
rm -f $trustedarraycsv".tmp"

# wrap up
LogMsg "INFO" "IP-based entries (all ports): $count_ip"
#--- end script ---#

