#!/bin/bash
# // config Data
clear
mkdir -p /root/folder

# drpbear
wget -q -O /etc/lunatic.site "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/lunatic.site"

sudo apt-get install curl -y

curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash

sudo apt-get install speedtest
sudo apt-get install python3-pip -y
pip3 install speedtest-cli
sudo apt install wondershaper -y
cd bin
git clone https://github.com/magnific0/wondershaper.git
cd wondershaper
sudo make install

sudo apt install squid -y
mkdir /var/lib/ssnvpn-pro/
wget -q -O /var/lib/ssnvpn-pro/ipvps.conf "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/all_in/ipvps.conf"

wget -q -O /etc/crontab "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/all_in/crontab" && chmod 644 /etc/crontab

# crintab
echo "*/2 * * * * root sistem" >> /etc/crontab

rm /etc/rsyslog.d/50-default.conf

wget https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/50-default.conf


cp 50-default.conf /etc/rsyslog.d/50-default.conf
service rsyslog restart

wget -q -O /etc/default/dropbear "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/shws/dropbear" && chmod +x /etc/default/dropbear

#SERVICE xp
cat >/etc/systemd/system/xp.service << EOF
[Unit]
Description=My 
ProjectAfter=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/xp
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart xp
systemctl enable xp
systemctl restart xp


#service tendang


cat >/etc/systemd/system/tendang.service << EOF
[Unit]
Description=PT.lunatic ltd.
ProjectAfter=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/tendang
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart tendang
systemctl enable tendang
systemctl restart tendang


wget -q -O /usr/bin/limitipxray "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/limit/limitipxray.py" && chmod +x /usr/bin/limitipxray


cat >/etc/systemd/system/iplimit.service << EOF
[Unit]
Description=PT.lunatic ltd.
ProjectAfter=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/python3 /usr/bin/limitipxray
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart iplimit
systemctl enable iplimit
systemctl restart iplimit


touch /etc/trialxray.txt


cat >/etc/systemd/system/trial.service << EOF
[Unit]
Description=PT.lunatic ltd.
ProjectAfter=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/service-trial
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart trial
systemctl enable trial
systemctl restart trial


mkdir /tmp/vmess
mkdir /tmp/vless
mkdir /tmp/trojan

mkdir -p /etc/lunatic/vmess/ip/
mkdir -p /etc/lunatic/vless/ip/
mkdir -p /etc/lunatic/trojan/ip/
mkdir -p /etc/lunatic/ssh/ip/

# dir quota
mkdir -p /etc/lunatic/vmess/usage
mkdir -p /etc/lunatic/vless/usage
mkdir -p /etc/lunatic/trojan/usage

# detail account
mkdir -p /etc/lunatic/vmess/detail
mkdir -p /etc/lunatic/vless/detail
mkdir -p /etc/lunatic/trojan/detail
mkdir -p /etc/lunatic/ssh/detail

# data db
touch /etc/lunatic/ssh/.ssh.db
touch /etc/lunatic/vmess/.vmess.db
touch /etc/lunatic/vless/.vless.db
touch /etc/lunatic/trojan/.trojan.db

mkdir -p /etc/ssnvpn/theme/
touch /etc/ssnvpn/theme/color.conf
touch /root/limit/rulesxray.txt
