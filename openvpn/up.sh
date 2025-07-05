#!/bin/bash
LOG_FILE="/var/log/openvpn-up.log"
ipnet=$(echo $4 | cut -d "." -f3)
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo $((100+$ipnet))  vpn$ipnet | tee  -a /etc/iproute2/rt_tables
ip rule add from 172.31.$ipnet.0/24 table vpn$ipnet
ip route add default table vpn$ipnet via $4 dev $1
iptables -t nat -A POSTROUTING -s 172.31.$ipnet.0/24 -j SNAT --to-source $4
{
    echo "============================================"
    echo "[$TIMESTAMP] VPN 连接已建立"
    echo "接口名称: $1"
    echo "接口类型: $( [ "$3" -eq 0 ] && echo "TUN" || echo "TAP" )"
    echo "本地IP地址: $4"
    echo "子网掩码: $5"
    echo "MTU: $2"
    echo "============================================"
    echo
} >> "$LOG_FILE"
