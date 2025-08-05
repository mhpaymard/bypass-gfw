#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}🔄 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Get domain or IP
echo "دامنه خود را وارد کنید (یا Enter برای استفاده از IP):"
read DOMAIN_NAME

if [[ -z "$DOMAIN_NAME" ]]; then
    DOMAIN_NAME="91.99.13.17"
    print_info "استفاده از IP: $DOMAIN_NAME"
else
    print_info "استفاده از دامنه: $DOMAIN_NAME"
fi

# Generate new UUID
UUID=$(cat /proc/sys/kernel/random/uuid)

print_status "تولید کانفیگ V2Ray جدید..."

# Create V2Ray config
cat > /usr/local/etc/v2ray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "alterId": 0,
            "security": "auto",
            "level": 0,
            "email": "user@$DOMAIN_NAME"
          }
        ],
        "default": {
          "level": 0,
          "alterId": 0
        },
        "disableInsecureEncryption": true
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "serverName": "$DOMAIN_NAME",
          "alpn": [
            "h2"
          ],
          "fingerprint": "chrome",
          "allowInsecure": false,
          "certificates": [
            {
              "certificateFile": "/etc/ssl/certs/advanced-gfw-bypass.crt",
              "keyFile": "/etc/ssl/private/advanced-gfw-bypass.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/static/images/logo.png",
          "headers": {
            "Host": "$DOMAIN_NAME",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

print_success "کانفیگ V2Ray تولید شد"

# Fix permissions
print_status "تنظیم مجوزهای فایل..."
sudo chown v2ray:v2ray /usr/local/etc/v2ray/config.json
sudo chown -R v2ray:v2ray /var/log/v2ray/

print_success "مجوزهای فایل تنظیم شد"

# Test config
print_status "تست کانفیگ V2Ray..."
if sudo /usr/local/bin/v2ray test -c /usr/local/etc/v2ray/config.json; then
    print_success "کانفیگ V2Ray صحیح است"
else
    print_error "کانفیگ V2Ray مشکل دارد"
    exit 1
fi

# Start V2Ray
print_status "راه‌اندازی V2Ray..."
sudo systemctl restart v2ray
sleep 3

# Check status
print_status "بررسی وضعیت V2Ray..."
if sudo systemctl is-active --quiet v2ray; then
    print_success "V2Ray فعال است"
else
    print_error "V2Ray فعال نیست"
    sudo journalctl -u v2ray -n 10
    exit 1
fi

# Save client config
print_status "تولید کانفیگ کلاینت..."
mkdir -p /root/bypass-gfw/advanced-gfw-bypass/configs

cat > /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json << EOF
{
  "server": "$DOMAIN_NAME",
  "port": 443,
  "uuid": "$UUID",
  "path": "/static/images/logo.png",
  "security": "tls",
  "network": "ws"
}
EOF

print_success "کانفیگ کلاینت تولید شد"
print_info "UUID: $UUID"
print_info "Server: $DOMAIN_NAME"
print_info "Path: /static/images/logo.png"

print_success "V2Ray با موفقیت کانفیگ و راه‌اندازی شد!" 