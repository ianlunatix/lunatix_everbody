#!/bin/bash
cd

apt install python -y


#System Dropbear Websocket-SSH Python
wget -O /usr/local/bin/ws_dropbear https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/shws/main/sshws.py && chmod +x /usr/local/bin/ws_dropbear
chmod +x /usr/local/bin/ws_dropbear
wget -O /etc/systemd/system/ws_dropbear.service https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/shws/dropbear_service && chmod +x /etc/systemd/system/ws_dropbear.service
chmod +x /usr/local/bin/ws_dropbear.service

systemctl daemon-reload
systemctl enable ws_dropbear.service
systemctl start ws_dropbear.service
systemctl restart ws_dropbear.service

#System SSL/TLS Websocket-SSH Python
wget -O /usr/local/bin/drop_py https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/shws/main/sshdropbear.py && chmod +x /usr/local/bin/drop_py
chmod +x /usr/local/bin/drop_py
wget -O /etc/systemd/system/ws_drop.service https://raw.githubusercontent.com/ianlunatix/lunatix_everbody/main/shws/ws_drop.service && chmod +x /etc/systemd/system/ws_drop.service
chmod +x /usr/local/bin/ws_drop.service

systemctl daemon-reload
systemctl enable ws_drop.service
systemctl start ws_drop.service
systemctl restart ws_drop.service

clear
