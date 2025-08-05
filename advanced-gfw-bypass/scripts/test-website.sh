#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

echo "=========================================="
echo "🌐 Testing Website and Connection"
echo "=========================================="

# Get domain from config or use default
DOMAIN=$(grep -o '"server": "[^"]*"' /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json | cut -d'"' -f4)
if [[ -z "$DOMAIN" ]]; then
    DOMAIN="dirdir.4doone.net"
fi

print_info "Testing domain: $DOMAIN"

# Test HTTPS connection
echo ""
print_info "Testing HTTPS connection..."
if curl -k -s -o /dev/null -w "%{http_code}" https://$DOMAIN/health | grep -q "200"; then
    print_success "HTTPS connection successful"
else
    print_error "HTTPS connection failed"
fi

# Test V2Ray WebSocket path
echo ""
print_info "Testing V2Ray WebSocket path..."
if curl -k -s -I https://$DOMAIN/static/images/logo.png | grep -q "200\|404"; then
    print_success "V2Ray path accessible"
else
    print_error "V2Ray path not accessible"
fi

# Show client configuration
echo ""
print_info "Client Configuration:"
echo "========================"
if [[ -f "/root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json" ]]; then
    cat /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json | jq '.' 2>/dev/null || cat /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json
else
    print_error "Client config file not found"
fi

# Show V2Ray status
echo ""
print_info "V2Ray Status:"
echo "==============="
systemctl status v2ray --no-pager -l

# Show open ports
echo ""
print_info "Open Ports:"
echo "============="
netstat -tlnp | grep -E ":(80|443|10086)" || echo "No relevant ports found"

# Test from external
echo ""
print_info "External connectivity test:"
echo "==============================="
EXTERNAL_IP=$(curl -s ifconfig.me 2>/dev/null || echo "Unknown")
print_info "Server IP: $EXTERNAL_IP"
print_info "Domain: $DOMAIN"

# QR Code for easy import (if qrencode is available)
if command -v qrencode &> /dev/null; then
    echo ""
    print_info "QR Code for V2RayNG:"
    echo "========================"
    CONFIG=$(cat /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json)
    echo "vmess://$(echo "$CONFIG" | base64 -w 0)" | qrencode -t ANSIUTF8
fi

echo ""
print_success "Testing completed!"
print_info "Use the client configuration above to connect from your phone/computer" 