#!/bin/bash
#
echo -e "\nRunning ${BASH_SOURCE[0]}"
#initialize vars
   source $(dirname $(readlink -f $0))/iptables.conf
   count_processed=0
   count_port=0
   count_ip=0

#parse source file
   trustedarraycsv=$(dirname $(readlink -f $0))/$rulespath/$whiteliststaticcsv
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

# check if port array is empty so a more generic rule is applied (specifies no ports)
    if [ ${#TrustedPorts[@]} -ne 0 ]; then
	for TrustedPort in ${TrustedPorts[@]}; do
        # LogMsg "DEBUG"  "Computed port is: "--$TrustedPort--""
    	    LogMsg "INFO"  "Processing port $TrustedPort for address $TrustedHost"
		$iptables -A INPUT -s ${TrustedHost} -p ${protocol} -m state --state NEW --dport ${TrustedPort} -i ${PUB1} -j ACCEPT -m comment --comment "INPUT Static $TrustedHost $host_desc"
#		$iptables -A INPUT -s ${TrustedHost} -p ${protocol} -m state --state NEW --sport ${TrustedPort} --dport ${TrustedPort} -i ${PUB1} -j ACCEPT -m comment --comment "INPUT Static $TrustedHost $host_desc"
       		LogMsg "INFO" "IP: $TrustedIP INPUT rule added for $TrustedHost -> "$host_desc" <-"
		$iptables -A OUTPUT -p ${protocol} -d ${TrustedHost} -m state --state NEW,ESTABLISHED --dport ${TrustedPort} -o ${PUB1} -j ACCEPT -m comment --comment "OUTPUT Static $TrustedHost $host_desc"
#		$iptables -A OUTPUT -p ${protocol} -d ${TrustedHost} -m state --state NEW,ESTABLISHED --dport ${TrustedPort} --sport ${TrustedPort} -o ${PUB1} -j ACCEPT -m comment --comment "OUTPUT Static $TrustedHost $host_desc"
       		LogMsg "INFO" "IP: $TrustedIP OUTPUT added for $TrustedHost -> "$host_desc" <-"
	done
		let count_port++
    else
	        LogMsg "INFO" "NO port specified, processing $TrustedHost for all ports"
    $iptables -A INPUT -s ${TrustedHost} -p ${protocol} -m state --state NEW -i ${PUB1} -j ACCEPT -m comment --comment "INPUT Static $TrustedHost $host_desc"
       		LogMsg "INFO" "IP: $TrustedIP INPUT rule added for $TrustedHost -> "$host_desc" <-"
    $iptables -A OUTPUT -p ${protocol} -d ${TrustedHost} -m state --state NEW,ESTABLISHED -o ${PUB1} -j ACCEPT -m comment --comment "OUTPUT Static $TrustedHost $host_desc"
      		LogMsg "INFO" "IP: $TrustedIP OUTPUT added for $TrustedHost. -> "$host_desc" <-"
		let count_ip++
    fi
let count_processed++
done < $trustedarraycsv".tmp"
#echo "" > $trustedarraycsv".tmp"
rm -f $trustedarraycsv".tmp"

# wrap up
LogMsg "INFO"
LogMsg "INFO" "Entries processed: $count_processed"
LogMsg "INFO" "Port-based entries: $count_port"
LogMsg "INFO" "IP-based entries (all ports): $count_ip"
#--- end script ---#

