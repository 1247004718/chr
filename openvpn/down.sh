
#!/bin/bash
LOG_FILE="/var/log/openvpn-down.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
ipnet=$(echo $4 | cut -d "." -f3)
iptables -t nat -D POSTROUTING -s 172.31.$ipnet.0/24 -j SNAT --to-source $4
ip rule del from 172.31.$ipnet.0/24 table vpn$ipnet
sed -i "/vpn$ipnet/d" /etc/iproute2/rt_tables
echo "[$TIMESTAMP] clear all ok."
##autodelete
##ip route del default table v1 via $4 dev $1
exit 0
