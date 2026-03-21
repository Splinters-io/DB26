#!/usr/bin/env bash
# DB26 — Interactsh Server Setup Script
# Provisions a VPS with interactsh-server for data bouncing
#
# Usage: ./setup.sh -d oob.yourdomain.com -i <VPS_PUBLIC_IP> [-t <AUTH_TOKEN>]
#
# Prerequisites:
#   - Root access on Ubuntu 22.04/24.04
#   - Domain NS records delegated to this VPS IP
#   - Ports 53, 80, 443, 25, 389, 445, 21 reachable

set -euo pipefail

# Defaults
DOMAIN=""
PUBLIC_IP=""
TOKEN=""
DISK_PATH="/var/lib/interactsh"
EVICTION_DAYS=90
LOG_DIR="/var/log/interactsh"

usage() {
    echo "Usage: $0 -d <domain> -i <public_ip> [-t <auth_token>]"
    echo "  -d  Domain for interactsh (e.g. oob.yourdomain.com)"
    echo "  -i  Public IP of this VPS"
    echo "  -t  Auth token (generated if omitted)"
    exit 1
}

while getopts ":d:i:t:" opt; do
    case ${opt} in
        d) DOMAIN=$OPTARG ;;
        i) PUBLIC_IP=$OPTARG ;;
        t) TOKEN=$OPTARG ;;
        *) usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && { echo "ERROR: -d domain is required"; usage; }
[[ -z "$PUBLIC_IP" ]] && { echo "ERROR: -i public IP is required"; usage; }

# Generate token if not provided
if [[ -z "$TOKEN" ]]; then
    TOKEN=$(openssl rand -hex 16)
    echo "[*] Generated auth token: $TOKEN"
    echo "[*] Save this token — you'll need it for the recruiter client"
fi

echo "================================================"
echo " DB26 Interactsh Server Setup"
echo " Domain:  $DOMAIN"
echo " IP:      $PUBLIC_IP"
echo " Token:   $TOKEN"
echo "================================================"

# 1. System updates and dependencies
echo "[1/7] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq screen wget curl git ufw

# 2. Install Go
echo "[2/7] Installing Go..."
if ! command -v go &>/dev/null; then
    GO_VERSION="1.22.5"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /root/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi
echo "    Go version: $(go version)"

# 3. Install interactsh-server
echo "[3/7] Installing interactsh-server..."
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest 2>&1 | tail -1
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>&1 | tail -1
echo "    interactsh-server installed at: $(which interactsh-server)"

# 4. Stop systemd-resolved (conflicts with port 53)
echo "[4/7] Configuring DNS (freeing port 53)..."
if systemctl is-active --quiet systemd-resolved; then
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    # Point resolv.conf to a public resolver
    rm -f /etc/resolv.conf
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    echo "    systemd-resolved stopped, using Cloudflare+Google DNS"
fi

# 5. Configure firewall
echo "[5/7] Configuring firewall..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 53/tcp    # DNS
ufw allow 53/udp    # DNS
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 25/tcp    # SMTP
ufw allow 389/tcp   # LDAP
ufw allow 445/tcp   # SMB
ufw allow 21/tcp    # FTP
ufw --force enable
echo "    Firewall configured"

# 6. Create directories and systemd service
echo "[6/7] Creating directories and service..."
mkdir -p "$DISK_PATH" "$LOG_DIR"

# Systemd service unit
cat > /etc/systemd/system/interactsh.service << SVCEOF
[Unit]
Description=Interactsh Server for DB26
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/root/go/bin/interactsh-server \
    -domain $DOMAIN \
    -ip $PUBLIC_IP \
    -token $TOKEN \
    -disk \
    -disk-path $DISK_PATH \
    -eviction $EVICTION_DAYS \
    -metrics \
    -debug
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/interactsh.log
StandardError=append:$LOG_DIR/interactsh.log

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload

# Screen launch script (manual fallback / stdout logging)
cat > /root/start-interactsh.sh << 'SCREOF'
#!/usr/bin/env bash
# Launch interactsh-server in a screen session with logging
SESSION_NAME="interactsh"
LOG_FILE="/var/log/interactsh/screen_$(date +%Y%m%d_%H%M%S).log"

# Kill existing session if present
screen -X -S "$SESSION_NAME" quit 2>/dev/null || true

# Start new screen session with logging
screen -dmS "$SESSION_NAME" -L -Logfile "$LOG_FILE" \
    /root/go/bin/interactsh-server \
    -domain DOMAIN_PLACEHOLDER \
    -ip IP_PLACEHOLDER \
    -token TOKEN_PLACEHOLDER \
    -disk \
    -disk-path /var/lib/interactsh \
    -eviction 90 \
    -metrics \
    -debug

echo "[*] interactsh-server started in screen session: $SESSION_NAME"
echo "[*] Logging to: $LOG_FILE"
echo "[*] Attach with: screen -r $SESSION_NAME"
SCREOF

# Replace placeholders in screen script
sed -i "s|DOMAIN_PLACEHOLDER|$DOMAIN|g" /root/start-interactsh.sh
sed -i "s|IP_PLACEHOLDER|$PUBLIC_IP|g" /root/start-interactsh.sh
sed -i "s|TOKEN_PLACEHOLDER|$TOKEN|g" /root/start-interactsh.sh
chmod +x /root/start-interactsh.sh

# 7. Start the service
echo "[7/7] Starting interactsh-server..."
systemctl enable interactsh
systemctl start interactsh

# Wait a moment then check status
sleep 3
if systemctl is-active --quiet interactsh; then
    echo ""
    echo "================================================"
    echo " SUCCESS — Interactsh Server Running"
    echo "================================================"
    echo " Domain:      $DOMAIN"
    echo " IP:          $PUBLIC_IP"
    echo " Token:       $TOKEN"
    echo " Disk:        $DISK_PATH"
    echo " Logs:        $LOG_DIR/interactsh.log"
    echo " Systemd:     systemctl status interactsh"
    echo " Screen alt:  /root/start-interactsh.sh"
    echo ""
    echo " Test with:"
    echo "   interactsh-client -server https://$DOMAIN -token $TOKEN"
    echo ""
    echo " DNS records needed in Cloudflare:"
    echo "   A    ns1.yourdomain.com      → $PUBLIC_IP  (DNS only, not proxied)"
    echo "   NS   oob.yourdomain.com      → ns1.yourdomain.com (DNS only)"
    echo "================================================"
else
    echo ""
    echo "[!] Service failed to start. Check logs:"
    echo "    journalctl -u interactsh -n 50"
    echo "    cat $LOG_DIR/interactsh.log"
fi

# Save config for reference
cat > /root/interactsh-config.env << CFGEOF
DOMAIN=$DOMAIN
PUBLIC_IP=$PUBLIC_IP
TOKEN=$TOKEN
DISK_PATH=$DISK_PATH
LOG_DIR=$LOG_DIR
EVICTION_DAYS=$EVICTION_DAYS
CFGEOF
echo "[*] Config saved to /root/interactsh-config.env"
