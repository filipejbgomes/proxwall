(crontab -l 2>/dev/null; echo "*/2 * * * * sh /root/IPTABLES/iptables_main.sh") | crontab -

ln -s /root/IPTABLES/iptables_main.sh /etc/network/if-pre-up.d/iptables

touch whitelist_dynamic.csv  
touch whitelist_dynamic.csv.tmp  
touch whitelist_static.csv
