#!/bin/bash
# Skrip untuk Instalasi dan Konfigurasi Xray + SSL pada OS Debian/Ubuntu

# Warna Output
red='\e[1;31m'
green='\e[1;32m'
yellow='\e[1;33m'
NC='\e[0m'

clear
echo -e "${green}Memulai konfigurasi layanan...${NC}"
date
echo ""

# Memastikan domain tersedia
if [ ! -f /root/domain ]; then
    echo -e "${red}Error: File domain tidak ditemukan!${NC}"
    exit 1
fi

domain=$(cat /root/domain)

# Instalasi dasar
echo -e "[ ${green}INFO${NC} ] Menginstal paket yang diperlukan..."
apt update && apt install -y iptables iptables-persistent curl socat xz-utils wget \
    apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release chrony zip pwgen \
    openssl netcat cron nginx bash-completion ntpdate >/dev/null 2>&1

# Sinkronisasi waktu
echo -e "[ ${green}INFO${NC} ] Menyinkronkan waktu..."
ntpdate pool.ntp.org
timedatectl set-ntp true
timedatectl set-timezone Asia/Jakarta
systemctl enable chronyd >/dev/null 2>&1
systemctl restart chronyd >/dev/null 2>&1
chronyc tracking >/dev/null 2>&1

# Mengunduh ACME untuk SSL
echo -e "[ ${green}INFO${NC} ] Mengonfigurasi sertifikat SSL..."
mkdir -p /etc/xray
mkdir -p /root/.acme.sh
curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
/root/.acme.sh/acme.sh --installcert -d $domain \
    --fullchainpath /etc/xray/xray.crt \
    --keypath /etc/xray/xray.key --ecc

# Konfigurasi SSL Nginx
echo -e "[ ${green}INFO${NC} ] Mengonfigurasi nginx..."
mkdir -p /home/vps/public_html
cat >/etc/nginx/conf.d/xray.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    listen 443 ssl http2 reuseport;
    listen [::]:443 http2 reuseport;
    server_name $domain;
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH;
    root /home/vps/public_html;
}
EOF

# Membuat skrip pembaruan SSL
echo -e "[ ${green}INFO${NC} ] Membuat skrip pembaruan SSL..."
cat >/usr/local/bin/ssl_renew.sh <<EOF
#!/bin/bash
systemctl stop nginx
/root/.acme.sh/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
systemctl start nginx
EOF
chmod +x /usr/local/bin/ssl_renew.sh

# Menambahkan cron job untuk pembaruan SSL otomatis
if ! crontab -l | grep -q 'ssl_renew.sh'; then
    (crontab -l; echo "15 3 */3 * * /usr/local/bin/ssl_renew.sh") | crontab -
fi

# Memulai ulang layanan
echo -e "[ ${green}INFO${NC} ] Memulai ulang layanan..."
systemctl daemon-reload
systemctl restart nginx
systemctl enable nginx

# Membersihkan file sementara
echo -e "[ ${green}INFO${NC} ] Pembersihan..."
rm -f /root/nginx-ssl.sh

# Output sukses
echo -e "${yellow}Konfigurasi selesai!${NC}"
echo -e "${green}Layanan xray dengan SSL telah dikonfigurasi.${NC}"
