#!/bin/bash

# اسکریپت نصب کامل سیستم v2ray با شبیه‌ساز ترافیک
# شامل Python و Node.js

set -e

# رنگ‌ها
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "این اسکریپت باید با دسترسی root اجرا شود"
        exit 1
    fi
}

update_system() {
    print_status "به‌روزرسانی سیستم..."
    apt update && apt upgrade -y
    print_success "سیستم به‌روزرسانی شد"
}

install_dependencies() {
    print_status "نصب وابستگی‌های سیستم..."
    
    # وابستگی‌های اصلی
    apt install -y curl wget unzip certbot nginx ufw git build-essential
    
    # وابستگی‌های Python
    apt install -y python3 python3-pip python3-venv python3-dev
    
    # وابستگی‌های Node.js
    apt install -y nodejs npm
    
    # به‌روزرسانی npm
    npm install -g npm@latest
    
    # نصب PM2 برای مدیریت پروسه‌ها
    npm install -g pm2
    
    print_success "وابستگی‌های سیستم نصب شدند"
}

install_v2ray() {
    print_status "نصب v2ray..."
    
    # دانلود و نصب v2ray
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    # ایجاد دایرکتوری‌های مورد نیاز
    mkdir -p /etc/v2ray/certs
    mkdir -p /var/log/v2ray
    mkdir -p /var/lib/v2ray
    
    print_success "v2ray نصب شد"
}

install_python_dependencies() {
    print_status "نصب وابستگی‌های Python..."
    
    # نصب وابستگی‌های Python
    pip3 install -r requirements.txt
    
    print_success "وابستگی‌های Python نصب شدند"
}

install_nodejs_dependencies() {
    print_status "نصب وابستگی‌های Node.js..."
    
    # نصب وابستگی‌های Node.js
    npm install
    
    print_success "وابستگی‌های Node.js نصب شدند"
}

setup_ssl_certificate() {
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

setup_nginx() {
    local domain=$1
    local web_port=$2
    local v2ray_port=$3
    
    print_status "تنظیم nginx..."
    
    # پیکربندی nginx
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
    
    # WebSocket برای v2ray
    location /api/v1/ws {
        proxy_pass http://127.0.0.1:$v2ray_port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # وب‌سایت اصلی
    location / {
        proxy_pass http://127.0.0.1:$web_port;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # API ها
    location /api/ {
        proxy_pass http://127.0.0.1:$web_port;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    # فعال‌سازی سایت
    ln -sf /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/
    
    # حذف سایت پیش‌فرض
    rm -f /etc/nginx/sites-enabled/default
    
    # تست و راه‌اندازی nginx
    nginx -t && systemctl restart nginx
    
    print_success "nginx تنظیم شد"
}

setup_firewall() {
    print_status "تنظیم فایروال..."
    
    # تنظیم قوانین
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    
    print_success "فایروال تنظیم شد"
}

create_systemd_services() {
    local domain=$1
    local web_port=$2
    
    print_status "ایجاد سرویس‌های systemd..."
    
    # سرویس Python
    cat > /etc/systemd/system/v2ray-traffic-simulator.service << EOF
[Unit]
Description=V2Ray Traffic Simulator (Python)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/usr/bin/python3 /root/realistic-traffic-simulator.py --domain $domain --port $web_port
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # سرویس Node.js
    cat > /etc/systemd/system/v2ray-nodejs-simulator.service << EOF
[Unit]
Description=V2Ray Node.js Traffic Simulator
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/usr/bin/node /root/traffic-simulator-nodejs.js $domain $web_port
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF
    
    # بارگذاری مجدد systemd
    systemctl daemon-reload
    
    print_success "سرویس‌های systemd ایجاد شدند"
}

setup_cron_jobs() {
    print_status "تنظیم کارهای زمان‌بندی شده..."
    
    # به‌روزرسانی خودکار گواهی SSL
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
    
    # پاک کردن لاگ‌های قدیمی
    (crontab -l 2>/dev/null; echo "0 2 * * * find /var/log/v2ray -name '*.log' -mtime +7 -delete") | crontab -
    
    # پشتیبان‌گیری از دیتابیس
    (crontab -l 2>/dev/null; echo "0 3 * * * cp /var/lib/v2ray/users.db /var/lib/v2ray/backup/users_\$(date +\%Y\%m\%d).db") | crontab -
    
    print_success "کارهای زمان‌بندی شده تنظیم شدند"
}

create_admin_user() {
    local admin_username=$1
    local admin_password=$2
    local admin_email=$3
    
    print_status "ایجاد کاربر ادمین..."
    
    # ایجاد کاربر ادمین با Python
    python3 -c "
import sqlite3
import hashlib
import uuid
from werkzeug.security import generate_password_hash

db_path = '/var/lib/v2ray/users.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# ایجاد کاربر ادمین
admin_uuid = str(uuid.uuid4())
password_hash = generate_password_hash('$admin_password')

cursor.execute('''
    INSERT OR REPLACE INTO users (username, password_hash, email, uuid, role)
    VALUES (?, ?, ?, ?, ?)
''', ('$admin_username', password_hash, '$admin_email', admin_uuid, 'admin'))

conn.commit()
conn.close()
print('کاربر ادمین ایجاد شد')
"
    
    print_success "کاربر ادمین ایجاد شد"
}

setup_monitoring() {
    print_status "تنظیم مانیتورینگ..."
    
    # نصب htop برای مانیتورینگ
    apt install -y htop iotop nethogs
    
    # ایجاد اسکریپت مانیتورینگ
    cat > /usr/local/bin/v2ray-monitor.sh << 'EOF'
#!/bin/bash

echo "=== V2Ray System Monitor ==="
echo "Date: $(date)"
echo ""

echo "=== System Resources ==="
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "Memory Usage: $(free | grep Mem | awk '{printf("%.2f%%", $3/$2 * 100.0)}')"
echo "Disk Usage: $(df -h / | awk 'NR==2 {print $5}')"
echo ""

echo "=== V2Ray Services ==="
systemctl is-active v2ray > /dev/null && echo "V2Ray: ✅ Active" || echo "V2Ray: ❌ Inactive"
systemctl is-active nginx > /dev/null && echo "Nginx: ✅ Active" || echo "Nginx: ❌ Inactive"
echo ""

echo "=== Traffic Statistics ==="
if [ -f /var/lib/v2ray/users.db ]; then
    sqlite3 /var/lib/v2ray/users.db "SELECT COUNT(*) as total_users FROM users WHERE is_active = 1;"
    sqlite3 /var/lib/v2ray/users.db "SELECT COUNT(DISTINCT user_id) as active_users FROM traffic_logs WHERE DATE(timestamp) = DATE('now');"
    sqlite3 /var/lib/v2ray/users.db "SELECT SUM(bytes_uploaded + bytes_downloaded) as total_traffic FROM traffic_logs WHERE DATE(timestamp) = DATE('now');"
fi
echo ""

echo "=== Network Connections ==="
netstat -tlnp | grep -E ':(80|443|8080|8443)' | head -5
EOF
    
    chmod +x /usr/local/bin/v2ray-monitor.sh
    
    print_success "مانیتورینگ تنظیم شد"
}

create_client_config_generator() {
    print_status "ایجاد تولیدکننده پیکربندی کلاینت..."
    
    cat > /usr/local/bin/generate-client-config.sh << 'EOF'
#!/bin/bash

if [ $# -ne 2 ]; then
    echo "استفاده: $0 <username> <domain>"
    exit 1
fi

USERNAME=$1
DOMAIN=$2
DB_PATH="/var/lib/v2ray/users.db"

# دریافت UUID کاربر
UUID=$(sqlite3 "$DB_PATH" "SELECT uuid FROM users WHERE username = '$USERNAME';")

if [ -z "$UUID" ]; then
    echo "کاربر $USERNAME یافت نشد"
    exit 1
fi

# تولید پیکربندی
cat > "v2ray-config-$USERNAME.json" << CONFIG
{
  "server": "$DOMAIN",
  "server_port": 443,
  "uuid": "$UUID",
  "alter_id": 0,
  "security": "tls",
  "network": "ws",
  "ws_opts": {
    "path": "/api/v1/ws",
    "headers": {
      "Host": "$DOMAIN"
    }
  }
}
CONFIG

echo "پیکربندی برای کاربر $USERNAME در فایل v2ray-config-$USERNAME.json ذخیره شد"
EOF
    
    chmod +x /usr/local/bin/generate-client-config.sh
    
    print_success "تولیدکننده پیکربندی کلاینت ایجاد شد"
}

show_final_info() {
    local domain=$1
    local admin_username=$2
    
    echo ""
    echo "=========================================="
    echo "🎉 نصب و راه‌اندازی کامل شد!"
    echo "=========================================="
    echo ""
    echo "📋 اطلاعات سیستم:"
    echo "🌐 دامنه: $domain"
    echo "🔌 پورت وب: 80/443"
    echo "🔌 پورت v2ray: 443"
    echo "👤 کاربر ادمین: $admin_username"
    echo ""
    echo "🔧 دستورات مفید:"
    echo "• مانیتورینگ: /usr/local/bin/v2ray-monitor.sh"
    echo "• تولید پیکربندی: /usr/local/bin/generate-client-config.sh <username> $domain"
    echo "• وضعیت سرویس‌ها: systemctl status v2ray nginx"
    echo "• مشاهده لاگ‌ها: tail -f /var/log/v2ray/access.log"
    echo ""
    echo "🌐 دسترسی‌ها:"
    echo "• وب‌سایت: https://$domain"
    echo "• API: https://$domain/api/"
    echo "• پنل ادمین: https://$domain/api/admin/"
    echo ""
    echo "📱 برای کلاینت‌های موبایل:"
    echo "• از V2RayNG استفاده کنید"
    echo "• پیکربندی را از ادمین دریافت کنید"
    echo ""
    echo "🔒 نکات امنیتی:"
    echo "• مرتباً رمز عبور ادمین را تغییر دهید"
    echo "• لاگ‌ها را بررسی کنید"
    echo "• از CDN استفاده کنید"
    echo ""
}

main() {
    echo "🚀 نصب کامل سیستم v2ray با شبیه‌ساز ترافیک"
    echo "================================================"
    
    # بررسی root بودن
    check_root
    
    # دریافت اطلاعات از کاربر
    read -p "🌐 دامنه سرور را وارد کنید: " domain
    read -p "📧 ایمیل برای گواهی SSL: " email
    read -p "👤 نام کاربری ادمین: " admin_username
    read -s -p "🔑 رمز عبور ادمین: " admin_password
    echo ""
    read -p "📧 ایمیل ادمین: " admin_email
    read -p "🔌 پورت وب سرور (80): " web_port
    web_port=${web_port:-80}
    read -p "🔌 پورت v2ray (443): " v2ray_port
    v2ray_port=${v2ray_port:-443}
    
    echo ""
    echo "انتخاب نوع شبیه‌ساز:"
    echo "1) Python (ساده)"
    echo "2) Node.js (پیشرفته)"
    echo "3) هر دو"
    read -p "انتخاب کنید (1-3): " simulator_choice
    
    # نصب و راه‌اندازی
    update_system
    install_dependencies
    install_v2ray
    setup_ssl_certificate $domain $email
    setup_nginx $domain $web_port $v2ray_port
    setup_firewall
    setup_cron_jobs
    setup_monitoring
    create_client_config_generator
    
    # نصب شبیه‌ساز انتخاب شده
    case $simulator_choice in
        1)
            install_python_dependencies
            create_systemd_services $domain $web_port
            systemctl enable v2ray-traffic-simulator.service
            systemctl start v2ray-traffic-simulator.service
            ;;
        2)
            install_nodejs_dependencies
            create_systemd_services $domain $web_port
            systemctl enable v2ray-nodejs-simulator.service
            systemctl start v2ray-nodejs-simulator.service
            ;;
        3)
            install_python_dependencies
            install_nodejs_dependencies
            create_systemd_services $domain $web_port
            systemctl enable v2ray-traffic-simulator.service
            systemctl enable v2ray-nodejs-simulator.service
            systemctl start v2ray-traffic-simulator.service
            systemctl start v2ray-nodejs-simulator.service
            ;;
    esac
    
    # راه‌اندازی سرویس‌ها
    systemctl enable v2ray
    systemctl start v2ray
    systemctl enable nginx
    systemctl start nginx
    
    # ایجاد کاربر ادمین
    create_admin_user $admin_username $admin_password $admin_email
    
    # نمایش اطلاعات نهایی
    show_final_info $domain $admin_username
    
    print_success "نصب و راه‌اندازی کامل شد!"
    print_warning "لطفاً اطلاعات اتصال را در جای امنی ذخیره کنید"
}

# اجرای تابع اصلی
main "$@" 