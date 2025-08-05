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
echo "🔧 Fixing UUID and Connectivity Issues"
echo "=========================================="

# Step 1: Check V2Ray config
print_info "Step 1: Checking V2Ray configuration..."

if [[ -f "/usr/local/etc/v2ray/config.json" ]]; then
    print_success "V2Ray config file exists"
    
    # Extract UUID
    UUID=$(grep -o '"id": "[^"]*"' /usr/local/etc/v2ray/config.json | cut -d'"' -f4 | head -1)
    
    if [[ -n "$UUID" ]]; then
        print_success "UUID found: $UUID"
    else
        print_error "UUID is empty or not found"
        
        # Generate new UUID
        NEW_UUID=$(cat /proc/sys/kernel/random/uuid)
        print_info "Generating new UUID: $NEW_UUID"
        
        # Update V2Ray config
        sed -i "s/\"id\": \"[^\"]*\"/\"id\": \"$NEW_UUID\"/g" /usr/local/etc/v2ray/config.json
        UUID="$NEW_UUID"
        print_success "V2Ray config updated with new UUID"
    fi
else
    print_error "V2Ray config file not found"
    exit 1
fi

# Step 2: Update client config
print_info "Step 2: Updating client configuration..."

if [[ -n "$UUID" ]]; then
    # Get domain from current config
    DOMAIN=$(grep -o '"server": "[^"]*"' /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json | cut -d'"' -f4)
    
    # Update client config
    cat > /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json << EOF
{
  "server": "$DOMAIN",
  "port": 443,
  "uuid": "$UUID",
  "path": "/static/images/logo.png",
  "security": "tls",
  "network": "ws"
}
EOF
    
    print_success "Client config updated with UUID: $UUID"
else
    print_error "Cannot update client config - UUID is empty"
fi

# Step 3: Restart V2Ray
print_info "Step 3: Restarting V2Ray..."
systemctl restart v2ray
sleep 3

# Step 4: Check V2Ray status
print_info "Step 4: Checking V2Ray status..."
if systemctl is-active --quiet v2ray; then
    print_success "V2Ray is running"
else
    print_error "V2Ray is not running"
    systemctl status v2ray --no-pager -l
fi

# Step 5: Check firewall and ports
print_info "Step 5: Checking firewall and ports..."

# Check if ports are open
if netstat -tlnp | grep -q ":443 "; then
    print_success "Port 443 is open"
else
    print_error "Port 443 is not open"
fi

if netstat -tlnp | grep -q ":80 "; then
    print_success "Port 80 is open"
else
    print_error "Port 80 is not open"
fi

# Check firewall status
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(ufw status | grep "Status: active")
    if [[ -n "$UFW_STATUS" ]]; then
        print_success "UFW firewall is active"
        ufw status numbered | grep -E "(80|443)"
    else
        print_warning "UFW firewall is not active"
    fi
fi

# Step 6: Test external connectivity
print_info "Step 6: Testing external connectivity..."

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "Unknown")
print_info "Server IP: $SERVER_IP"

# Test from external perspective
print_info "Testing external access..."

# Test HTTP
if curl -s -o /dev/null -w "%{http_code}" http://$SERVER_IP/health | grep -q "200\|301\|302"; then
    print_success "HTTP external access works"
else
    print_error "HTTP external access failed"
fi

# Test HTTPS
if curl -k -s -o /dev/null -w "%{http_code}" https://$SERVER_IP/health | grep -q "200"; then
    print_success "HTTPS external access works"
else
    print_error "HTTPS external access failed"
fi

# Test domain
if curl -k -s -o /dev/null -w "%{http_code}" https://dirdir.4doone.net/health | grep -q "200"; then
    print_success "Domain external access works"
else
    print_error "Domain external access failed"
fi

# Step 7: Show final configuration
print_info "Step 7: Final configuration:"
echo "================================"
echo "Server: $DOMAIN"
echo "UUID: $UUID"
echo "Port: 443"
echo "Path: /static/images/logo.png"
echo "Security: TLS"
echo "Network: WebSocket"
echo ""

# Show client config
print_info "Client configuration file:"
cat /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json

echo ""
print_success "UUID fix completed!"
print_info "If external access still doesn't work, check your domain DNS settings" 