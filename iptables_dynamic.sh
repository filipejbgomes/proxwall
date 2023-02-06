#!/bin/bash

echo -e "\nRunning ${BASH_SOURCE[0]}"
#initialize vars
   source $(dirname $(readlink -f $0))/iptables.conf
   count_processed=0
   count_invalid=0
   count_valid=0
   OLDIFS=$IFS

#parse source file
  trustedarraycsv=$(dirname $(readlink -f $0))/$rulespath/$whitelistdynamiccsv
   sed -i '/^\s*$/d' $trustedarraycsv
   sed -e '/^[[:space:]]*#/d' $trustedarraycsv > $trustedarraycsv".tmp"
   LogMsg "INFO" "Parsing File: $trustedarraycsv"
   IFS=$'\n'
   while read line ; do
       protocol=$(awk -F" " '{print $1}' <<<"$line")
       TrustedHost=$(echo ${line} |awk -F" " '{print $2}' |  cut -d ':' -f 1|awk '{ sub(/^[ \t]+/, ""); print }')
       host_desc=$(awk -F"#" '{print $2}' <<<"$line")

#--- read comma-separated port list from current rule into separate array---#
# input syntax:"tcp hostname.com:80,22,443# description"
      TrustedPorts=()
      IFS=$',' read -r -a TrustedPorts <<<$(echo ${line} |awk -F":" '{print $2}' |  cut -d '#' -f 1|sed 's/[^0-9,]*//g')
      IFS=$'\n'

#  rm -f $trustedarraycsv".tmp"
  #echo "" > $trustedarraycsv".tmp"

#Trusted hosts list (DDNS)
 if [[ $TrustedHost =~ ^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$ ]]; then
     TrustedIP=$(/usr/bin/dig in a +short $TrustedHost )

 fi
	LogMsg "INFO" "Resolved IP from Host: $TrustedIP"
        if [[ $TrustedHost =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TrustedHost=$TrustedIP
	fi

        if [[ $TrustedIP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

#collect old trusted ip's
	read -r -a OldTrustedIP_in <<< $(sudo iptables -L -n --line-numbers |grep $protocol |grep "$TrustedHost" |grep "INPUT:Dynamic"|awk -F" " '{ print $1 }')
	read -r -a OldTrustedIP_out <<< $(sudo iptables -L -n --line-numbers |grep $protocol | grep "$TrustedHost" |grep "OUTPUT:Dynamic"|awk -F" " '{ print $1 }')

# check if port array is empty so a more generic rule is applied (specifies no ports)
    if [ ${#TrustedPorts[@]} -ne 0 ]; then
	for TrustedPort in ${TrustedPorts[@]}; do
#         LogMsg "DEBUG"  "Computed port is: "--$TrustedPort--""
    	    LogMsg "INFO"  "Processing port $TrustedPort for address $TrustedHost"
		$iptables -A INPUT -s ${TrustedIP} -d ${PUB1_ADDR} -p ${protocol} -m state --state NEW --dport ${TrustedPort} -j ACCEPT -m comment --comment "INPUT:Dynamic $TrustedHost $host_desc"
       		LogMsg "INFO" "IP: $TrustedIP INPUT rule added for $TrustedHost -> "$host_desc" <-"
		$iptables -A OUTPUT -p ${protocol} -s ${PUB1_ADDR} -d ${TrustedIP} -m state --state NEW,ESTABLISHED --dport ${TrustedPort}  -j ACCEPT -m comment --comment "OUTPUT:Dynamic $TrustedHost $host_desc"
       		LogMsg "INFO" "IP: $TrustedIP OUTPUT added for $TrustedHost -> "$host_desc" <-"
	done
		let count_port++
	    else
		        LogMsg "INFO" "NO port specified, processing $TrustedHost for all $protocol ports"
    		$iptables -A INPUT -s ${TrustedIP} -d ${PUB1_ADDR} -p ${protocol} -m state --state NEW -j ACCEPT -m comment --comment "INPUT:Dynamic DNS: $TrustedHost $host_desc"
       			LogMsg "INFO" "IP: $TrustedIP INPUT rule added for $TrustedHost -> "$host_desc" <-"
    		$iptables -A OUTPUT -p ${protocol} -d ${TrustedIP} -s ${PUB1_ADDR} -m state --state NEW,ESTABLISHED  -j ACCEPT -m comment --comment "OUTPUT:Dynamic DNS: $TrustedHost $host_desc"
      			LogMsg "INFO" "IP: $TrustedIP OUTPUT added for $TrustedHost. -> "$host_desc" <-"
		let count_ip++
    fi

# clean old INPUT entries
	for x in "${OldTrustedIP_in[@]}"; do
	LogMsg "INFO" "removing old INPUT rule: $x"
	$iptables -D INPUT $x
	done
	OldTrustedIP_in=()

# clean old OUTPUT entries
	for x in "${OldTrustedIP_out[@]}"; do
	LogMsg "INFO" "removing old OUTPUT rule: $x"
	$iptables -D OUTPUT $x
	done

 	OldTrustedIP_out=()
	LogMsg "INFO" "IP: $TrustedIP resolved and added successfully from $TrustedHost"
        let count_valid++
        else

# deal with bad dns/unresolvable
          LogMsg "ERROR" "Could not resolve IP correctly from DNS name provided"
	  let count_invalid++
        fi
let count_processed++
done < $trustedarraycsv".tmp"
#echo "" > $trustedarraycsv".tmp"
rm -f $trustedarraycsv".tmp"

# wrap up
LogMsg "INFO"
LogMsg "INFO" "entries processed: $count_processed"
LogMsg "INFO" "non-resolvable entries: $count_invalid"
LogMsg "INFO" "valid entries: $count_valid"
IFS=$OLDIFS
#--- end script ---#
