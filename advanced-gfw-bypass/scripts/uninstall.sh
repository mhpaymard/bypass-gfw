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

echo "=========================================="
echo "🗑️  Advanced GFW Bypass System - Uninstall"
echo "=========================================="

# Stop all services
print_status "متوقف کردن سرویس‌ها..."
systemctl stop v2ray 2>/dev/null
systemctl stop nginx 2>/dev/null
systemctl stop redis-server 2>/dev/null
systemctl stop traffic-simulator 2>/dev/null
systemctl stop domain-manager 2>/dev/null
systemctl stop monitoring 2>/dev/null

# Disable services
print_status "غیرفعال کردن سرویس‌ها..."
systemctl disable v2ray 2>/dev/null
systemctl disable traffic-simulator 2>/dev/null
systemctl disable domain-manager 2>/dev/null
systemctl disable monitoring 2>/dev/null

# Remove systemd service files
print_status "حذف فایل‌های systemd..."
rm -f /etc/systemd/system/v2ray.service
rm -f /etc/systemd/system/traffic-simulator.service
rm -f /etc/systemd/system/domain-manager.service
rm -f /etc/systemd/system/monitoring.service

# Remove V2Ray
print_status "حذف V2Ray..."
rm -rf /usr/local/bin/v2ray
rm -rf /usr/local/etc/v2ray
rm -rf /usr/local/share/v2ray
rm -rf /var/log/v2ray

# Remove SSL certificates
print_status "حذف SSL certificates..."
rm -f /etc/ssl/certs/advanced-gfw-bypass.crt
rm -f /etc/ssl/private/advanced-gfw-bypass.key
rm -f /etc/ssl/certs/your-domain.com.crt
rm -f /etc/ssl/private/your-domain.com.key

# Remove Nginx config
print_status "حذف کانفیگ Nginx..."
rm -f /etc/nginx/sites-available/advanced-gfw-bypass
rm -f /etc/nginx/sites-enabled/advanced-gfw-bypass

# Remove firewall rules
print_status "حذف قوانین firewall..."
ufw delete allow 80/tcp 2>/dev/null
ufw delete allow 443/tcp 2>/dev/null
ufw delete allow 8080/tcp 2>/dev/null
ufw delete allow 8443/tcp 2>/dev/null

# Remove user
print_status "حذف user v2ray..."
userdel v2ray 2>/dev/null
groupdel v2ray 2>/dev/null

# Remove application files
print_status "حذف فایل‌های برنامه..."
rm -rf /root/bypass-gfw/advanced-gfw-bypass

# Reload systemd
print_status "Reload systemd..."
systemctl daemon-reload

# Clean up logs
print_status "پاک کردن لاگ‌ها..."
journalctl --vacuum-time=1s 2>/dev/null

print_success "Uninstall کامل شد!"
echo ""
print_warning "برای نصب مجدد: cd /root && git clone <repo> && cd bypass-gfw/advanced-gfw-bypass/scripts && bash install.sh" 