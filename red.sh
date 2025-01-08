#!/bin/bash
IP_VPS=$(curl -sS ipv4.icanhazip.com)

IP_VPS=$(wget -qO- ipinfo.io/ip);
echo -e "\e[93;1mComprueba tu VPS \e[0m"
sleep 0.5
CEKEXPIRED () {
today=$(date -d +1day +%Y -%m -%d)
Exp1=$(curl -sS https://raw.githubusercontent.com/messiey/rocky/master/gerung | grep $IP_VPS | awk '{print $3}')
if [[ $today < $Exp1 ]]; then
echo -e "\e[92;1m Scripts Remainders \e[0m"
else
echo -e "\e[91;1mScripts Failure type expires! \e[0m";
exit 0
fi
}
PERMISO_ACCESO=$(curl -sS https://raw.githubusercontent.com/messiey/rocky/master/gerung | awk '{print $4}' | grep $IP_VPS)
if [ $IP_VPS = $PERMISO_ACCESO ]; then
echo "PERMISO_ACCESO DI TERIMA!!"
else
echo -e "\e[91;1mAkses di tolak!! Silakan Hubungi Admin \e[0m";
exit 0
fi
localip=$(hostname -I | cut -d\  -f1)
hst=( `hostname` )
dart=$(cat /etc/hosts | grep -w `hostname` | awk '{print $2}')
if [[ "$hst" != "$dart" ]]; then
echo "$localip $(hostname)" >> /etc/hosts
fi
if [ -f "/root/log-install.txt" ]; then
rm -fr /root/log-install.txt
fi
mkdir -p /etc/xray
mkdir -p /etc/v2ray
touch /etc/xray/domain
touch /etc/v2ray/domain
touch /etc/xray/scdomain
touch /etc/v2ray/scdomain
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
apt install git curl -y >/dev/null 2>&1
apt install python -y >/dev/null 2>&1
echo -e "[ \e[92;1mINFO\e[0m ] \e[93;1mSe permiten guiones \e[0m"
sleep 2
mkdir -p /var/lib/LT >/dev/null 2>&1
echo "IP=" >> /var/lib/LT/ipvps.conf
sudo apt install vnstat
sudo apt insta squid
wget -q -O https://raw.githubusercontent.com/messiey/rocky/master/tools.sh && chmod +x tools.sh && ./tools.sh
rm tools.sh
clear
clear
echo -e "\e[91;1m ==================================== \e[0m"
echo -e "\e[91;1m            MASUKAN DOMAIN              \e[0m"
echo -e "\e[91;1m ==================================== \e[0m"
echo " "
read -rp " Input ur domain : " -e pp
if [ -z $pp ]; then
echo -e "
Nothing input for domain!
Then a random domain will be created"
else
echo "$pp" > /root/scdomain
echo "$pp" > /etc/xray/scdomain
echo "$pp" > /etc/xray/domain
echo "$pp" > /etc/v2ray/domain
echo $pp > /root/domain
echo "IP=$pp" > /var/lib/LT/ipvps.conf
fi
clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[92;1m      Install SSH / WS / UDP              \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear
curl "https://raw.githubusercontent.com/messiey/rocky/master/menu/ssh-vpn.sh" | bash
sleep 2
wget https://raw.githubusercontent.com/messiey/rocky/master/nginx-ssl.sh && chmod +x nginx-ssl.sh && ./nginx-ssl.sh
wget -q -O demeling.sh https://raw.githubusercontent.com/messiey/rocky/master/demeling.sh && chmod +x demeling.sh && ./demeling.sh
cd
mkdir -p /root/udp
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
echo downloading udp-custom
wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=12safUbdfI6kUEfb1MBRxlDfmV8NAaJmb' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=12safUbdfI6kUEfb1MBRxlDfmV8NAaJmb" -O /root/udp/udp-custom && rm -rf /tmp/cookies.txt
chmod +x /root/udp/udp-custom
echo downloading default config
wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf" -O /root/udp/config.json && rm -rf /tmp/cookies.txt
if [ -z "$1" ]; then
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=udp-custom by ©CyberVPN
[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s
[Install]
WantedBy=default.target
EOF
else
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=udp-custom by ©CyberVPN
[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server -exclude $1
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s
[Install]
WantedBy=default.target
EOF
fi
echo start service udp-custom
systemctl start udp-custom &>/dev/null
echo enable service udp-custom
systemctl enable udp-custom &>/dev/null
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[92;1m      Install Websocket              \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear
curl "https://raw.githubusercontent.com/messiey/rocky/master/Insshws/insshws.sh" | bash
cd /usr/bin
wget -O xp "https://raw.githubusercontent.com/messiey/rocky/master/menu/xp.sh"
chmod +x xp
sleep 1
wget -q -O /usr/bin/notramcpu "https://raw.githubusercontent.com/messiey/rocky/master/Finaleuy/notramcpu" && chmod +x /usr/bin/notramcpu
cd
rm -f /root/ins-xray.sh
rm -f /root/insshws.sh
rm -f /root/xraymode.sh
clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[92;1m      Install ALL XRAY               \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
curl "https://raw.githubusercontent.com/messiey/rocky/master/menu/insray.sh" | bash
sleep 1
curl "https://raw.githubusercontent.com/messiey/rocky/master/arca.sh" | bash
sleep 1
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[92;1m      Install slowdns               \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
wget -q -O slowdns.sh https://raw.githubusercontent.com/messiey/rocky/master/SLDNS/slowdns.sh && chmod +x slowdns.sh && ./slowdns.sh
mkdir /root/akun
mkdir /root/akun/vmess
mkdir /root/akun/vless
mkdir /root/akun/shadowsocks
mkdir /root/akun/trojan
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[92;1m      Install IPSEC L2TP & SSTP               \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 1
curl "https://raw.githubusercontent.com/messiey/rocky/master/ipsec/ipsec.sh" | bash
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[92;1m      Install OPENVPN             \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
wget "https://raw.githubusercontent.com/messiey/rocky/master/Insshws/vpn.sh" && bash vpn.sh && rm vpn.sh
clear

# Telegram Variable
USERID=5039581855
KEY="6670926441:AAHQnHzPxJaVy0WZD4kov4C3ZFPj8pqBjMk"
TIMEOUT="10"
URL="https://api.telegram.org/bot$KEY/sendMessage"
DATE_EXEC="$(date "+%d %b %Y %H:%M")"
TMPFILE='/tmp/ipinfo-$DATE_EXEC.txt'
if [ -n "$SSH_CLIENT" ] && [ -z "$TMUX" ]; then
IP=$(echo $SSH_CLIENT | awk '{print $1}')
PORT=$(echo $SSH_CLIENT | awk '{print $3}')
HOSTNAME=$(hostname -f)
IPADDR=$(hostname -I | awk '{print $1}')
curl http://ipinfo.io/$IP -s -o $TMPFILE
CITY=$(cat $TMPFILE | sed -n 's/^  "city":[[:space:]]*//p' | sed 's/"//g')
REGION=$(cat $TMPFILE | sed -n 's/^  "region":[[:space:]]*//p' | sed 's/"//g')
COUNTRY=$(cat $TMPFILE | sed -n 's/^  "country":[[:space:]]*//p' | sed 's/"//g')
ORG=$(cat $TMPFILE | sed -n 's/^  "org":[[:space:]]*//p' | sed 's/"//g')
TEXT="
==============================
🕊 Informasi instalasi script 🕊
==============================
🎲Tanggal: $DATE_EXEC
🎲Domain: $(cat /etc/xray/domain) 
🎲Status: Telah menginstall scriptmu
🎲Hostname  : $HOSTNAME 
🎲Publik IP :$IPADDR 
🎲IP PROV   : $IP 
🎲ISP       : $ORG
🎲KOTA      : $CITY
🎲PROVINSI  : $REGION
🎲PORT SSH. : $PORT
=============================="
curl -s --max-time $TIMEOUT -d "chat_id=$USERID&disable_web_page_preview=1&text=$TEXT" $URL > /dev/null
rm $TMPFILE
fi

# crontab Variable
echo "0 5 * * * root reboot" >> /etc/crontab
echo "* * * * * root clog" >> /etc/crontab
echo "59 * * * * root pkill 'menu'" >> /etc/crontab
echo "0 1 * * * root xp" >> /etc/crontab
echo "*/5 * * * * root notramcpu" >> /etc/crontab
service cron restart
clear
org=$(curl -s https://ipapi.co/org )
echo "$org" > /root/.isp

# profle Variable
cat> /root/.profile << END
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
clear
menu1
END
chmod 644 /root/.profile
if [ -f "/root/log-install.txt" ]; then
rm -fr /root/log-install.txt
fi
cd
echo "1.0.0" > versi
clear
rm -f ins-xray.sh
rm -f senmenu.sh
rm -f setupku.sh
rm -f xraymode.sh
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22, 53, 2222, 2269"  | tee -a log-install.txt
echo "   - SSH Websocket           : 80" | tee -a log-install.txt
echo "   - SSH SSL Websocket       : 443" | tee -a log-install.txt
echo "   - Stunnel5                : 222, 777" | tee -a log-install.txt
echo "   - Dropbear                : 109, 143" | tee -a log-install.txt
echo "   - Badvpn                  : 7100-7300" | tee -a log-install.txt
echo "   - Nginx                   : 81" | tee -a log-install.txt
echo "   - XRAY  Vmess TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vmess None TLS    : 80" | tee -a log-install.txt
echo "   - XRAY  Vless TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vless None TLS    : 80" | tee -a log-install.txt
echo "   - Trojan GRPC             : 443" | tee -a log-install.txt
echo "   - Trojan WS               : 443" | tee -a log-install.txt
echo "   - Trojan GO               : 443" | tee -a log-install.txt
echo "   - Sodosok WS/GRPC         : 443" | tee -a log-install.txt
echo "   - SLOWDNS                 : 53"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo ""
echo -e ""
echo ""
echo "" | tee -a log-install.txt
echo "Installasi Autoscript Sukses"
sleep 1
echo -ne "[ ${yell}WARNING${NC} ] Do you want to reboot now ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi