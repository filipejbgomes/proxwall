
# read config file
[[ ! -f $(dirname $(readlink -f $0))/iptables.conf ]] && { echo "Config file not found, exiting!"; exit 1; }
source $(dirname $(readlink -f $0))/iptables.conf

# Reset/Flush chains
$iptables -P INPUT ACCEPT
$iptables -P OUTPUT ACCEPT
$iptables -P FORWARD ACCEPT
$iptables -F
$iptables -t nat -F
$iptables -t mangle -F
$iptables -X


