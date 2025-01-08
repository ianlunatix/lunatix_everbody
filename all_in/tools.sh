#!/bin/bash
# Skrip Instalasi Tools untuk Debian & Ubuntu

# Warna untuk output
red='\e[1;31m'
green='\e[1;32m'
yellow='\e[1;33m'
NC='\e[0m' # No Color

# Fungsi untuk mencetak pesan dengan warna
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }

clear
echo -e "${green}Memulai instalasi tools...${NC}"
sleep 2

# Memeriksa OS yang digunakan
if [[ -e /etc/debian_version ]]; then
    source /etc/os-release
    OS=$ID # debian atau ubuntu
else
    echo -e "${red}OS tidak didukung! Skrip ini hanya untuk Debian atau Ubuntu.${NC}"
    exit 1
fi

echo -e "${yellow}Menghapus aplikasi yang tidak diperlukan...${NC}"
sudo apt update -y
sudo apt-get remove --purge -y ufw firewalld exim4 apache2 >/dev/null 2>&1

echo -e "${yellow}Menginstal dependensi yang diperlukan...${NC}"
sudo apt install -y screen curl jq bzip2 gzip coreutils rsyslog iftop \
    htop zip unzip net-tools sed gnupg gnupg1 bc sudo apt-transport-https \
    build-essential dirmngr libxml-parser-perl neofetch screenfetch git \
    lsof openssl fail2ban tmux stunnel4 vnstat squid dropbear libsqlite3-dev \
    socat cron bash-completion ntpdate xz-utils gnupg2 dnsutils lsb-release chrony

# Instalasi Node.js
echo -e "${yellow}Menginstal Node.js...${NC}"
curl -sSL https://deb.nodesource.com/setup_16.x | bash -
sudo apt-get install -y nodejs >/dev/null 2>&1

# Konfigurasi vnStat
echo -e "${yellow}Menginstal dan mengonfigurasi vnStat...${NC}"
wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz >/dev/null 2>&1
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
cd ..
vnstat -u -i eth0
sed -i 's/Interface "eth0"/Interface "eth0"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat >/dev/null 2>&1
/etc/init.d/vnstat restart
rm -rf vnstat-2.6 vnstat-2.6.tar.gz >/dev/null 2>&1

# Instalasi tambahan
echo -e "${yellow}Menginstal layanan tambahan...${NC}"
sudo apt install -y libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev \
    libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools \
    libevent-dev xl2tpd pptpd >/dev/null 2>&1

echo -e "${green}Dependencies berhasil diinstal.${NC}"
sleep 3
clear
