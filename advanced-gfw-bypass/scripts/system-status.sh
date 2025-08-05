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

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

echo "=========================================="
echo "🔍 بررسی کامل وضعیت سیستم GFW Bypass"
echo "=========================================="

# Check V2Ray
echo ""
print_status "بررسی V2Ray..."
if systemctl is-active --quiet v2ray; then
    print_success "V2Ray: فعال"
    V2RAY_PORT=$(netstat -tlnp 2>/dev/null | grep v2ray | awk '{print $4}' | cut -d: -f2 | head -1)
    if [[ -n "$V2RAY_PORT" ]]; then
        print_info "پورت V2Ray: $V2RAY_PORT"
    fi
else
    print_error "V2Ray: غیرفعال"
    echo "لاگ V2Ray:"
    journalctl -u v2ray -n 5 --no-pager
fi

# Check Nginx
echo ""
print_status "بررسی Nginx..."
if systemctl is-active --quiet nginx; then
    print_success "Nginx: فعال"
    NGINX_PORTS=$(netstat -tlnp 2>/dev/null | grep nginx | awk '{print $4}' | cut -d: -f2 | sort -u)
    if [[ -n "$NGINX_PORTS" ]]; then
        print_info "پورت‌های Nginx: $NGINX_PORTS"
    fi
else
    print_error "Nginx: غیرفعال"
fi

# Check Redis
echo ""
print_status "بررسی Redis..."
if systemctl is-active --quiet redis-server; then
    print_success "Redis: فعال"
else
    print_error "Redis: غیرفعال"
fi

# Check SSL Certificates
echo ""
print_status "بررسی SSL Certificates..."
if [[ -f "/etc/ssl/certs/advanced-gfw-bypass.crt" ]]; then
    print_success "SSL Certificate: موجود"
    CERT_EXPIRY=$(openssl x509 -in /etc/ssl/certs/advanced-gfw-bypass.crt -noout -enddate 2>/dev/null | cut -d= -f2)
    if [[ -n "$CERT_EXPIRY" ]]; then
        print_info "تاریخ انقضا: $CERT_EXPIRY"
    fi
else
    print_error "SSL Certificate: موجود نیست"
fi

# Check Firewall
echo ""
print_status "بررسی Firewall..."
if ufw status | grep -q "Status: active"; then
    print_success "Firewall: فعال"
    UFW_RULES=$(ufw status numbered | grep -E "(80|443|8080|8443)" | wc -l)
    print_info "قوانین پورت‌های اصلی: $UFW_RULES"
else
    print_warning "Firewall: غیرفعال"
fi

# Check Ports
echo ""
print_status "بررسی پورت‌های فعال..."
OPEN_PORTS=$(netstat -tlnp 2>/dev/null | grep -E ":(80|443|8080|8443)" | awk '{print $4}' | cut -d: -f2 | sort -u)
if [[ -n "$OPEN_PORTS" ]]; then
    print_success "پورت‌های باز: $OPEN_PORTS"
else
    print_error "هیچ پورت اصلی باز نیست"
fi

# Check V2Ray Config
echo ""
print_status "بررسی کانفیگ V2Ray..."
if [[ -f "/usr/local/etc/v2ray/config.json" ]]; then
    if /usr/local/bin/v2ray test -c /usr/local/etc/v2ray/config.json >/dev/null 2>&1; then
        print_success "کانفیگ V2Ray: صحیح"
        
        # Extract info from config
        UUID=$(grep -o '"id": "[^"]*"' /usr/local/etc/v2ray/config.json | cut -d'"' -f4 | head -1)
        SERVER_NAME=$(grep -o '"serverName": "[^"]*"' /usr/local/etc/v2ray/config.json | cut -d'"' -f4 | head -1)
        WS_PATH=$(grep -o '"path": "[^"]*"' /usr/local/etc/v2ray/config.json | cut -d'"' -f4 | head -1)
        
        if [[ -n "$UUID" ]]; then
            print_info "UUID: $UUID"
        fi
        if [[ -n "$SERVER_NAME" ]]; then
            print_info "Server Name: $SERVER_NAME"
        fi
        if [[ -n "$WS_PATH" ]]; then
            print_info "WebSocket Path: $WS_PATH"
        fi
    else
        print_error "کانفیگ V2Ray: مشکل دارد"
    fi
else
    print_error "فایل کانفیگ V2Ray موجود نیست"
fi

# Check Client Config
echo ""
print_status "بررسی کانفیگ کلاینت..."
if [[ -f "/root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json" ]]; then
    print_success "کانفیگ کلاینت: موجود"
    CLIENT_SERVER=$(grep -o '"server": "[^"]*"' /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json | cut -d'"' -f4)
    CLIENT_UUID=$(grep -o '"uuid": "[^"]*"' /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json | cut -d'"' -f4)
    if [[ -n "$CLIENT_SERVER" ]]; then
        print_info "Server: $CLIENT_SERVER"
    fi
    if [[ -n "$CLIENT_UUID" ]]; then
        print_info "UUID: $CLIENT_UUID"
    fi
else
    print_warning "کانفیگ کلاینت موجود نیست"
fi

# System Resources
echo ""
print_status "بررسی منابع سیستم..."
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)

print_info "CPU Usage: ${CPU_USAGE}%"
print_info "Memory Usage: ${MEMORY_USAGE}%"
print_info "Disk Usage: ${DISK_USAGE}%"

# Summary
echo ""
echo "=========================================="
echo "📊 خلاصه وضعیت سیستم"
echo "=========================================="

ACTIVE_SERVICES=0
TOTAL_SERVICES=3

if systemctl is-active --quiet v2ray; then ((ACTIVE_SERVICES++)); fi
if systemctl is-active --quiet nginx; then ((ACTIVE_SERVICES++)); fi
if systemctl is-active --quiet redis-server; then ((ACTIVE_SERVICES++)); fi

if [[ $ACTIVE_SERVICES -eq $TOTAL_SERVICES ]]; then
    print_success "همه سرویس‌ها فعال هستند! 🎉"
elif [[ $ACTIVE_SERVICES -gt 0 ]]; then
    print_warning "$ACTIVE_SERVICES از $TOTAL_SERVICES سرویس فعال است"
else
    print_error "هیچ سرویسی فعال نیست!"
fi

echo ""
print_info "برای راه‌اندازی مجدد: systemctl restart v2ray nginx redis-server"
print_info "برای مشاهده لاگ‌ها: journalctl -u v2ray -f"
print_info "کانفیگ کلاینت در: /root/bypass-gfw/advanced-gfw-bypass/configs/" 