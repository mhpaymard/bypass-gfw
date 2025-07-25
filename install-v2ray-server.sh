#!/bin/bash

# اسکریپت نصب و راه‌اندازی v2ray با قابلیت دور زدن GFW
# برای سیستم‌های Ubuntu/Debian

set -e

# رنگ‌ها برای خروجی
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# تابع نمایش پیام
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# بررسی root بودن
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "این اسکریپت باید با دسترسی root اجرا شود"
        exit 1
    fi
}

# به‌روزرسانی سیستم
update_system() {
    print_status "به‌روزرسانی سیستم..."
    apt update && apt upgrade -y
    print_success "سیستم به‌روزرسانی شد"
}

# نصب وابستگی‌ها
install_dependencies() {
    print_status "نصب وابستگی‌ها..."
    apt install -y curl wget unzip certbot nginx
    print_success "وابستگی‌ها نصب شدند"
}

# نصب v2ray
install_v2ray() {
    print_status "نصب v2ray..."
    
    # دانلود و نصب v2ray
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    # ایجاد دایرکتوری‌های مورد نیاز
    mkdir -p /etc/v2ray/certs
    mkdir -p /var/log/v2ray
    
    print_success "v2ray نصب شد"
}

# تولید UUID تصادفی
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# تولید مسیر تصادفی
generate_random_path() {
    paths=(
        "/api/v1/ws"
        "/websocket/stream"
        "/proxy/connect"
        "/cdn/static"
        "/api/rest"
        "/graphql"
        "/socket.io"
        "/live/stream"
        "/chat/ws"
        "/notification/ws"
    )
    echo "${paths[$RANDOM % ${#paths[@]}]}"
}

# تولید نام سرویس تصادفی
generate_random_service() {
    services=(
        "grpc"
        "api"
        "service"
        "proxy"
        "stream"
        "chat"
        "live"
        "cdn"
        "api-gateway"
        "microservice"
    )
    echo "${services[$RANDOM % ${#services[@]}]}"
}

# تولید فینگرپرینت تصادفی
generate_fingerprint() {
    fingerprints=("chrome" "firefox" "safari" "edge")
    echo "${fingerprints[$RANDOM % ${#fingerprints[@]}]}"
}

# تولید پیکربندی WebSocket
generate_websocket_config() {
    local domain=$1
    local port=$2
    local uuid=$3
    local path=$4
    local fingerprint=$5
    
    cat > /etc/v2ray/config.json << EOF
{
  "inbounds": [{
    "port": $port,
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "$uuid",
        "alterId": 0
      }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": {
        "path": "$path",
        "headers": {
          "Host": "$domain"
        }
      },
      "tlsSettings": {
        "serverName": "$domain",
        "fingerprint": "$fingerprint",
        "alpn": ["h2", "http/1.1"],
        "certificates": [{
          "certificateFile": "/etc/v2ray/certs/$domain.pem",
          "keyFile": "/etc/v2ray/certs/$domain.key"
        }]
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }],
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  }
}
EOF
}

# تولید پیکربندی HTTP/2
generate_h2_config() {
    local domain=$1
    local port=$2
    local uuid=$3
    local path=$4
    local fingerprint=$5
    
    cat > /etc/v2ray/config.json << EOF
{
  "inbounds": [{
    "port": $port,
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "$uuid",
        "alterId": 0
      }]
    },
    "streamSettings": {
      "network": "h2",
      "security": "tls",
      "httpSettings": {
        "host": ["$domain"],
        "path": "$path"
      },
      "tlsSettings": {
        "serverName": "$domain",
        "fingerprint": "$fingerprint",
        "alpn": ["h2", "http/1.1"],
        "certificates": [{
          "certificateFile": "/etc/v2ray/certs/$domain.pem",
          "keyFile": "/etc/v2ray/certs/$domain.key"
        }]
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }],
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  }
}
EOF
}

# تولید پیکربندی gRPC
generate_grpc_config() {
    local domain=$1
    local port=$2
    local uuid=$3
    local service=$4
    local fingerprint=$5
    
    cat > /etc/v2ray/config.json << EOF
{
  "inbounds": [{
    "port": $port,
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "$uuid",
        "alterId": 0
      }]
    },
    "streamSettings": {
      "network": "grpc",
      "security": "tls",
      "grpcSettings": {
        "serviceName": "$service"
      },
      "tlsSettings": {
        "serverName": "$domain",
        "fingerprint": "$fingerprint",
        "alpn": ["h2", "http/1.1"],
        "certificates": [{
          "certificateFile": "/etc/v2ray/certs/$domain.pem",
          "keyFile": "/etc/v2ray/certs/$domain.key"
        }]
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }],
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  }
}
EOF
}

# نصب گواهی SSL
install_ssl_certificate() {
    local domain=$1
    local email=$2
    
    print_status "نصب گواهی SSL برای $domain..."
    
    # توقف nginx موقتاً
    systemctl stop nginx
    
    # نصب گواهی
    certbot certonly --standalone -d $domain --email $email --agree-tos --non-interactive
    
    # کپی گواهی‌ها
    cp /etc/letsencrypt/live/$domain/fullchain.pem /etc/v2ray/certs/$domain.pem
    cp /etc/letsencrypt/live/$domain/privkey.pem /etc/v2ray/certs/$domain.key
    
    # تنظیم مجوزها
    chown v2ray:v2ray /etc/v2ray/certs/$domain.pem
    chown v2ray:v2ray /etc/v2ray/certs/$domain.key
    chmod 600 /etc/v2ray/certs/$domain.pem
    chmod 600 /etc/v2ray/certs/$domain.key
    
    print_success "گواهی SSL نصب شد"
}

# تنظیم nginx برای CDN
setup_nginx() {
    local domain=$1
    local port=$2
    
    cat > /etc/nginx/sites-available/$domain << EOF
server {
    listen 80;
    server_name $domain;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain;
    
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    location / {
        proxy_pass http://127.0.0.1:$port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    # فعال‌سازی سایت
    ln -sf /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/
    
    # تست و راه‌اندازی nginx
    nginx -t && systemctl restart nginx
    
    print_success "nginx تنظیم شد"
}

# تنظیم فایروال
setup_firewall() {
    print_status "تنظیم فایروال..."
    
    # نصب ufw اگر نصب نیست
    apt install -y ufw
    
    # تنظیم قوانین
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    
    print_success "فایروال تنظیم شد"
}

# راه‌اندازی سرویس‌ها
start_services() {
    print_status "راه‌اندازی سرویس‌ها..."
    
    systemctl enable v2ray
    systemctl start v2ray
    systemctl enable nginx
    systemctl start nginx
    
    print_success "سرویس‌ها راه‌اندازی شدند"
}

# نمایش اطلاعات اتصال
show_connection_info() {
    local domain=$1
    local uuid=$2
    local path=$3
    local network=$4
    local port=$5
    
    echo ""
    echo "=========================================="
    echo "🔗 اطلاعات اتصال v2ray"
    echo "=========================================="
    echo "🌐 دامنه: $domain"
    echo "🔌 پورت: $port"
    echo "🔑 UUID: $uuid"
    echo "🛣️ مسیر: $path"
    echo "🌍 شبکه: $network"
    echo "🔒 امنیت: TLS"
    echo "=========================================="
    echo ""
    echo "📱 برای کلاینت‌های موبایل از V2RayNG استفاده کنید"
    echo "💻 برای ویندوز از v2rayN استفاده کنید"
    echo "🔄 مرتباً UUID و مسیرها را تغییر دهید"
    echo ""
}

# تابع اصلی
main() {
    echo "🚀 نصب و راه‌اندازی v2ray با قابلیت دور زدن GFW"
    echo "================================================"
    
    # بررسی root بودن
    check_root
    
    # دریافت اطلاعات از کاربر
    read -p "🌐 دامنه سرور را وارد کنید: " domain
    read -p "📧 ایمیل برای گواهی SSL: " email
    read -p "🔌 پورت سرور (443): " port
    port=${port:-443}
    
    echo ""
    echo "انتخاب نوع پروتکل:"
    echo "1) WebSocket (توصیه شده)"
    echo "2) HTTP/2"
    echo "3) gRPC"
    read -p "انتخاب کنید (1-3): " protocol_choice
    
    # تولید مقادیر تصادفی
    uuid=$(generate_uuid)
    fingerprint=$(generate_fingerprint)
    
    case $protocol_choice in
        1)
            network="ws"
            path=$(generate_random_path)
            generate_websocket_config $domain $port $uuid $path $fingerprint
            ;;
        2)
            network="h2"
            path=$(generate_random_path)
            generate_h2_config $domain $port $uuid $path $fingerprint
            ;;
        3)
            network="grpc"
            path=$(generate_random_service)
            generate_grpc_config $domain $port $uuid $path $fingerprint
            ;;
        *)
            print_error "انتخاب نامعتبر"
            exit 1
            ;;
    esac
    
    # نصب و راه‌اندازی
    update_system
    install_dependencies
    install_v2ray
    install_ssl_certificate $domain $email
    setup_nginx $domain $port
    setup_firewall
    start_services
    
    # نمایش اطلاعات
    show_connection_info $domain $uuid $path $network $port
    
    print_success "نصب و راه‌اندازی کامل شد!"
    print_warning "لطفاً اطلاعات اتصال را در جای امنی ذخیره کنید"
}

# اجرای تابع اصلی
main "$@" 