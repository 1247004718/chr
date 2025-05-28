#!/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
## qq:1247004718
##======================
SPW=admin888888
USERNAME_DEF=a111
PASSWORD_DEF=888888
##====================
macradon() {
FIXED_OUI="5E-99-9E"
RANDOM_BYTES=$(openssl rand -hex 3 | fold -w 2 | paste -sd '-' -)
FULL_MAC="${FIXED_OUI}-${RANDOM_BYTES}"
echo "$FULL_MAC"
}
#added 2025-05-28
dnsrenew() {
resolvectl status | grep -q stub
if [  $? -eq  0 ]; then
    rm /etc/resolv.conf
    ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf

fi
}

INTERVAL=1
PIP=$(curl ip.sb)
DEFAULT_HOST=localhost
DEFAULT_HUB=DEFAULT
MACHR=$(echo $(macradon) | tr a-z A-Z)

install_vpn() {
pkill vpnserver
rm -rf /usr/bin/vpnserver
rm -f vpn.tar.gz
rm -f vpn.conf
rm -f nft.nat
URL=https://www.softether-download.com/files/softether/v4.42-9798-rtm-2023.06.30-tree/Linux/SoftEther_VPN_Server/64bit_-_Intel_x64_or_AMD64/softether-vpnserver-v4.42-9798-rtm-2023.06.30-linux-x64-64bit.tar.gz
wget -O vpn.tar.gz $URL 2>&1 > /dev/null
if [[ $? -ne 0 ]];then
		echo -e "Download Failed" && exit 4
	    fi
tar -zxvf vpn.tar.gz 2>&1 > /dev/null
cd vpnserver && make 2>&1 > /dev/null
cd ..
cp -a vpnserver /usr/bin/ 2>&1 >/dev/null 

echo '
[Unit]
Description=SSTP VPN Server
After=network.target network-online.target
[Service]
ExecStart=/usr/bin/vpnserver/vpnserver start
ExecStop=/usr/bin/vpnserver/vpnserver stop
Type=forking
RestartSec=3s
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/vpnserver.service

systemctl daemon-reload && systemctl enable vpnserver
systemctl start vpnserver  && echo -e "\n\n vpnserver start!" && sleep 2

}
pre_conf() {
	clear
	#echo ""
	IPTHR=$(echo  $[$RANDOM%255])
	USERNAME=${USERNAME_DEF}
	PASSWORD=${PASSWORD_DEF}
	ADDRESS="172.29.$IPTHR.0/24"
	IPADDR=`echo $ADDRESS | cut -d. -f1-3`
	start=10 
	end=100
	echo SstpEnable yes | tee -a vpn.conf
	echo hub Default | tee -a vpn.conf
	echo UserCreate $USERNAME /GROUP:none /REALNAME:none /NOTE:none | tee -a vpn.conf
	echo UserPasswordSet $USERNAME /PASSWORD:$PASSWORD | tee -a vpn.conf
	echo SecureNatEnable | tee -a vpn.conf
	echo SecureNatHostSet /MAC:$MACHR /IP:${IPADDR}.$start /MASK:255.255.255.0 | tee -a vpn.conf
	echo DhcpSet /START:${IPADDR}.$start /END:${IPADDR}.$end /MASK:255.255.255.0 /EXPIRE:7200 /GW:${IPADDR}.$start /DNS:8.8.8.8 /DNS2:8.8.4.4 /DOMAIN:" " /LOG:no | tee -a vpn.conf
	echo ServerPasswordSet ${SPW} | tee -a vpn.conf
	clear
	/usr/bin/vpnserver/vpncmd localhost:5555 /server /csv /in:vpn.conf 2>&1 > /dev/null
	rm -rf vpnserver vpn.conf vpn.tar.gz 2>&1 > /dev/null
	echo ""
	echo "SSTP Server : $PIP User: $USERNAME PASS:$PASSWORD" > ~/user.txt
	echo "SSTP Server: $PIP User: $USERNAME PASS:$PASSWORD"

}	
nftnat() {
	systemctl enable nftables
	echo '
#!/usr/sbin/nft -f
#
flush ruleset
table ip nat {
    chain postrouting {
            type nat hook postrouting priority 100; policy accept;
                      masquerade
                        }

	 }' > /etc/nftables.conf
	 systemctl start nftables
	 echo "net.ipv4.ip_forward=1" | tee -a /etc/sysctl.conf && sysctl -p
}
apt update -y && apt install nftables build-essential nftables -y
install_vpn
nftnat
clear
pre_conf
dnsrenew
