#!/bin/bash

# Log
LOG_FILE="/tmp/install.log"

# Enable xtrace and redirect all output and errors to the log file
exec > >(tee -a "$LOG_FILE") 2>&1
set -x 

# Prepare the system, we need mysql only for the client for the setup
yum update
yum install -y golang git mysql
useradd --system --no-create-home --shell /usr/sbin/nologin trillian

# Build and install trillian_log_server. It needs to happen separately so we do not
# hit user_data limits
tee /root/trillian_install.sh > /dev/null <<EOF
git clone https://github.com/google/trillian
cd trillian
go build -tags=mysql ./cmd/trillian_log_server
cp trillian_log_server /usr/bin/
go build -tags=mysql ./cmd/trillian_log_signer
cp trillian_log_signer /usr/bin/
EOF

chmod +x /root/trillian_install.sh

cat <<EOF > /etc/systemd/system/trillian-install.service
[Unit]
Description=Run Trillian installation script only once immediately
After=network.target

[Service]
RuntimeDirectory=trillian
WorkingDirectory=/run/trillian
Environment=GOPATH=/root/gopath
Environment=GOMODCACHE=/root/gomodcache
Environment=GOCACHE=/root/gocache
ExecStart=/bin/bash /root/trillian_install.sh
Type=oneshot
RemainAfterExit=true
ExecStartPost=/bin/systemctl disable trillian-install.service
ExecStartPost=/bin/touch /var/run/trillian-setup-complete

[Install]
WantedBy=multi-user.target
EOF

systemctl enable trillian-install.service

# Start the service immediately
systemctl start trillian-install.service

# Prepare mysql for trillian
# TODO: host should not be a wildcard but... PoC
mysql -u ${root_user} -p${root_password} -h ${host} <<EOF
CREATE DATABASE IF NOT EXISTS ${trillian_db};
CREATE USER IF NOT EXISTS '${trillian_user}'@'%' IDENTIFIED BY '${trillian_password}';
GRANT ALL PRIVILEGES ON \`${trillian_user}\`.* TO '${trillian_db}'@'%';
FLUSH PRIVILEGES;
EOF

curl -o storage.sql https://raw.githubusercontent.com/google/trillian/refs/heads/master/storage/mysql/schema/storage.sql
mysql -u ${trillian_user} -p"${trillian_password}" "${trillian_db}" -h ${host} < < storage.sql
rm storage.sql

# Create trillian config file
mkdir /etc/trillian
tee /etc/trillian/server_config > /dev/null <<EOF
--mysql_uri=${trillian_user}:${trillian_password}@tcp(${host})/${trillian_db}
--rpc_endpoint=0.0.0.0:8090 
--http_endpoint=0.0.0.0:8091
EOF
# Set secure permissions
chmod 400 /etc/trillian/server_config
chown trillian:trillian /etc/trillian/server_config

tee /etc/trillian/signer_config > /dev/null <<EOF
--mysql_uri=${trillian_user}:${trillian_password}@tcp(${host})/${trillian_db}
--rpc_endpoint=127.0.0.1:9090 
--http_endpoint=127.0.0.1:9091
--force_master
EOF
# Set secure permissions
chmod 400 /etc/trillian/signer_config
chown trillian:trillian /etc/trillian/signer_config

tee /etc/systemd/system/trillian-server.service > /dev/null <<EOF
[Unit]
Description=Trillian Log Server
After=network.target trillian-install.service
Requires=trillian-install.service
ConditionPathExists=/var/run/trillian-setup-complete

[Service]
User=trillian
Group=trillian
WorkingDirectory=/run/trillian
ExecStart=/usr/bin/trillian_log_server -config /etc/trillian/server_config
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
RuntimeDirectory=trillian
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

tee /etc/systemd/system/trillian-signer.service > /dev/null <<EOF
[Unit]
Description=Trillian Log Server
After=network.target trillian-install.service
Requires=trillian-install.service
ConditionPathExists=/var/run/trillian-setup-complete

[Service]
User=trillian
Group=trillian
WorkingDirectory=/run/trillian
ExecStart=/usr/bin/trillian_log_signer -config /etc/trillian/signer_config
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
RuntimeDirectory=trillian
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable trillian-server
systemctl enable trillian-signer
systemctl start trillian-server
systemctl start trillian-signer