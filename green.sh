#!/bin/bash

# Get VPS IP address
IP_VPS=$(curl -sS ipv4.icanhazip.com)

# Function to check permission
check_permission() {
    today=$(date -d "+1 day" "+%Y-%m-%d")
    Exp1=$(curl -sS https://raw.githubusercontent.com/ianlunatix/ip_access/main/ip | grep "$IP_VPS" | awk '{print $3}')
    
    if [[ $today < $Exp1 ]]; then
        echo -e "\e[92;1mPermission Granted\e[0m"
    else
        echo -e "\e[91;1mScripts Expired\e[0m"
        exit 1
    fi
}

# Function to verify access
verify_access() {
    DATA_PERMISSION=$(curl -sS https://raw.githubusercontent.com/ianlunatix/ip_access/main/ip | awk '{print $4}' | grep "$IP_VPS")
    
    if [[ "$IP_VPS" == "$DATA_PERMISSION" ]]; then
        echo -e "\e[92;1mAccess Granted\e[0m"
    else
        echo -e "\e[91;1mAccess Denied!\e[0m"
        exit 1
    fi
}

# Set hostname and update /etc/hosts
setup_hostname() {
    localip=$(hostname -I | cut -d' ' -f1)
    hostname=$(hostname)
    dart=$(grep -w "$hostname" /etc/hosts | awk '{print $2}')
    
    if [[ "$hostname" != "$dart" ]]; then
        echo "$localip $hostname" >> /etc/hosts
    fi
}

# Prepare directories and files
prepare_environment() {
    mkdir -p /etc/xray /etc/v2ray /var/lib/LT
    touch /etc/xray/domain /etc/v2ray/domain /etc/xray/scdomain /etc/v2ray/scdomain
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
    echo "IP=" > /var/lib/LT/ipvps.conf
}

# Install required packages
install_dependencies() {
    wget -q -O dep https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/all_in/tools.sh
    chmod +x dep
    ./dep
    rm dep
}    

# Main function
main() {
    # Permission and access checks
    check_permission
    verify_access

    # Setup environment
    setup_hostname
    prepare_environment

    # Install dependencies and tools
    install_dependencies

    # Clean up and final message
    if [[ -f /root/log-install.txt ]]; then
        rm -f /root/log-install.txt
    fi
    clear
    echo -e "[\e[92;1mINFO\e[0m] \e[96;1mSetup complete. Your system is ready.\e[0m"
}

# Execute the main function
main

# Fungsi untuk mengatur domain
setup_domain() {
    clear
    echo -e "\e[91;1m ==================================== \e[0m"
    echo -e "\e[91;1m            MASUKKAN DOMAIN           \e[0m"
    echo -e "\e[91;1m ==================================== \e[0m"
    echo ""
    read -rp " Input your domain: " -e INPUT_HOST

    if [ -z "$INPUT_HOST" ]; then
        echo -e "\e[91;1mTidak ada domain yang dimasukkan! Domain acak akan dibuat.\e[0m"
    else
        echo "$INPUT_HOST" > /root/scdomain
        echo "$INPUT_HOST" > /etc/xray/scdomain
        echo "$INPUT_HOST" > /etc/xray/domain
        echo "$INPUT_HOST" > /etc/v2ray/domain
        echo "$INPUT_HOST" > /root/domain
        echo "IP=$INPUT_HOST" > /var/lib/LT/ipvps.conf
    fi
    sleep 2
    clear
}

# Fungsi untuk menginstal SSH dan VPN
install_ssh_vpn() {
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\e[92;1m      Install SSH / WS / UDP        \e[0m"
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    sleep 2
    clear
    curl "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/shws/ssh-vpn.sh" | bash
    sleep 2

    wget https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/all_in/nginx-ssl.sh -O nginx-ssl.sh
    chmod +x nginx-ssl.sh
    ./nginx-ssl.sh

    wget -q -O demeling.sh https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/all_in/vnstats.sh
    chmod +x vnstats.sh
    ./vnstats.sh
    clear
}

# Fungsi untuk menginstal dan mengkonfigurasi UDP Custom
install_udp_custom() {
    echo -e "Mengunduh UDP Custom..."
    mkdir -p /root/udp
    wget -q --show-progress --load-cookies /tmp/cookies.txt \
        "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate \
        'https://docs.google.com/uc?export=download&id=12safUbdfI6kUEfb1MBRxlDfmV8NAaJmb' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=12safUbdfI6kUEfb1MBRxlDfmV8NAaJmb" \
        -O /root/udp/udp-custom && rm -rf /tmp/cookies.txt
    chmod +x /root/udp/udp-custom

    echo -e "Mengunduh konfigurasi default..."
    wget -q --show-progress --load-cookies /tmp/cookies.txt \
        "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate \
        'https://docs.google.com/uc?export=download&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf" \
        -O /root/udp/config.json && rm -rf /tmp/cookies.txt

    # Buat file service
    echo -e "Mengonfigurasi layanan UDP Custom..."
    cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ©LunatixTUNNEL

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

    # Memulai layanan
    echo -e "Memulai layanan UDP Custom..."
    systemctl start udp-custom &>/dev/null
    systemctl enable udp-custom &>/dev/null
    echo -e "UDP Custom berhasil diinstal dan dikonfigurasi."
}
# Fungsi untuk menginstal WebSocket
install_websocket() {
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\e[92;1m      Install Websocket              \e[0m"
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    sleep 2
    clear
    curl "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/shws/shws.sh" | bash

}

# Fungsi untuk menginstal XRAY
install_xray() {
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\e[92;1m      Install ALL XRAY               \e[0m"
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    sleep 2
    curl "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/xray/insray.sh" | bash
    curl "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/all_in/arca.sh" | bash
    echo -e "XRAY installation completed."
    sleep 2
}

# Fungsi untuk menginstal SlowDNS
install_menu() {
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\e[92;1m      Install dash menu               \e[0m"
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    sleep 2
    
REPO="https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/"

    clear
    wget ${REPO}dash/LunatiX
    unzip LunatiX
    chmod +x luna/*
    mv luna/* /usr/bin
    rm -rf luna
    rm -rf LunatiX

    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
dashboard
EOF

echo " menu sukses "
# Memberikan izin untuk .profile
chmod 644 /root/.profile
}
# Fungsi untuk menyiapkan direktori akun
setup_account_directories() {
    echo -e "Creating account directories..."

# dir utama
    tr="trojan"
    vm="vmess"
    vl="vless"
    mkdir -p /etc/lunatic
    mkdir -p /etc/limit
    mkdir -p /etc/limit/$vm
    mkdir -p /etc/limit/$vl
    mkdir -p /etc/limit/$tr            
# dir protocol    
    mkdir -p /etc/lunatic/vmess
    mkdir -p /etc/lunatic/vless    
    mkdir -p /etc/lunatic/trojan
    mkdir -p /etc/lunatic/ssh
# dir bot
    mkdir -p /etc/lunatic/bot
    mkdir -p /etc/lunatic/bot/notif    
# dir akun    
    mkdir -p /etc/lunatic/vmess/detail
    mkdir -p /etc/lunatic/vless/detail   
    mkdir -p /etc/lunatic/trojan/detail
    mkdir -p /etc/lunatic/ssh/detail
# dir db
    mkdir -p /etc/lunatic/vmess/.vmess.db
    mkdir -p /etc/lunatic/vless/.vless.db   
    mkdir -p /etc/lunatic/trojan/.trojan.db
    mkdir -p /etc/lunatic/ssh/.ssh.db
    
    echo -e "Account directories created successfully."
}


# Fungsi untuk menginstal OpenVPN
install_openvpn() {
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\e[92;1m      Install OPENVPN               \e[0m"
    echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    wget "https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/shws/vpn.sh" -O vpn.sh
    chmod +x vpn.sh
    ./vpn.sh
    rm -f vpn.sh
    echo -e "OpenVPN installation completed."
    sleep 2
}
notificasi() {
clear
# Konfigurasi Telegram
USERID=50395818
KEY="6779682523:AAELp5uMfacZ9B4ZEKKONcYqnFFqWhP5h0"
TIMEOUT="10"
URL="https://api.telegram.org/bot$KEY/sendMessage"

# Informasi Waktu
DATE_EXEC="$(date "+%d %b %Y %H:%M")"

# File sementara untuk menyimpan info IP
TMPFILE="/tmp/ipinfo-$(date "+%Y%m%d%H%M").txt"

# Deteksi sesi SSH dan informasi pengguna
if [ -n "$SSH_CLIENT" ] && [ -z "$TMUX" ]; then
    IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
    PORT=$(echo "$SSH_CLIENT" | awk '{print $3}')
    HOSTNAME=$(hostname -f)
    IPADDR=$(hostname -I | awk '{print $1}')
    
    # Mendapatkan informasi IP menggunakan ipinfo.io
    curl -s http://ipinfo.io/$IP -o $TMPFILE
    
    CITY=$(grep '"city"' $TMPFILE | awk -F': "' '{print $2}' | sed 's/",//g')
    REGION=$(grep '"region"' $TMPFILE | awk -F': "' '{print $2}' | sed 's/",//g')
    COUNTRY=$(grep '"country"' $TMPFILE | awk -F': "' '{print $2}' | sed 's/",//g')
    ORG=$(grep '"org"' $TMPFILE | awk -F': "' '{print $2}' | sed 's/",//g')
    
    # Pesan notifikasi
    TEXT="
==============================
❤️‍🔥 Informasi Instalasi Script ❤️‍🔥
==============================
🎲 Tanggal   : $DATE_EXEC
🎲 Domain    : $(cat /etc/xray/domain 2>/dev/null || echo 'Domain tidak ditemukan')
🎲 Hostname  : $HOSTNAME
🎲 Publik IP : $IPADDR
🎲 IP Prov   : $IP
🎲 ISP       : $ORG
🎲 Kota      : $CITY
🎲 Provinsi  : $REGION
🎲 Port SSH  : $PORT
=============================="

    # Mengirim notifikasi ke Telegram
    curl -s --max-time $TIMEOUT -d "chat_id=$USERID&disable_web_page_preview=1&text=$TEXT" $URL > /dev/null
    
    # Membersihkan file sementara
    rm -f $TMPFILE
fi
}
finishing_profile() {
clear
# Penjadwalan Cron Jobs
echo "0 5 * * * root reboot" >> /etc/crontab
echo "* * * * * root clog" >> /etc/crontab
echo "59 * * * * root pkill 'menu'" >> /etc/crontab
echo "0 1 * * * root xp" >> /etc/crontab
echo "*/5 * * * * root notramcpu" >> /etc/crontab

# Restart layanan cron
service cron restart
clear

# Mendapatkan nama ISP
org=$(curl -s https://ipapi.co/org)
echo "$org" > /root/.isp

# Hapus log pemasangan lama jika ada
if [ -f "/root/log-install.txt" ]; then
    rm -f /root/log-install.txt
fi

# Set versi aplikasi
cd
echo "1.0.0" > versi

# Membersihkan file instalasi sementara
rm -f insray.sh wtf.sh xraymode.sh
clear
}

ports() {
echo ""
echo "   >>> Service & Port" | tee -a log-install.txt
echo "   - OpenSSH                 : 22, 53, 2222, 2269" | tee -a log-install.txt
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
echo "   - SLOWDNS                 : 53" | tee -a log-install.txt
echo "" | tee -a log-install.txt

echo "   >>> Server Information & Other Features" | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)" | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]" | tee -a log-install.txt
echo "   - Dflate                  : [ON]" | tee -a log-install.txt
echo "   - IPtables                : [ON]" | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]" | tee -a log-install.txt
echo "   - IPv6                    : [OFF]" | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully Automatic Script" | tee -a log-install.txt
echo "   - VPS Settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change Port" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo ""

# Pesan akhir
echo "ADIOS" | tee -a log-install.txt
sleep 1

# Konfirmasi reboot
echo -ne "[ WARNING ] Do you want to reboot now? (y/n): "
read -r answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    reboot
else
    echo "Reboot canceled. Exiting..."
    exit 0
fi
}
# Fungsi utama
execute() {
    # Ubah timezone ke Asia/Jakarta
    echo -e "Mengatur timezone ke Asia/Jakarta..."
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # setup domain input
    setup_domain
    
    # Install ssh_vpn    
    install_ssh_vpn
    
   # Install udp custom
    install_udp_custom
    
    # Install WebSocket
    install_websocket

    # Install XRAY
    install_xray

    # Install SlowDNS
    install_menu

    # Setup account directories
    setup_account_directories    

    # Install OpenVPN
    install_openvpn

    # Pemberitahuan
    notificasi

    # Finish Profile
    finishing_profile
    
    # information ports
    ports
    
    # clear screen
    clear
    
    # Selesai
    echo -e "Semua proses selesai. Sistem siap digunakan!"
}

# Eksekusi fungsi utama
execute
