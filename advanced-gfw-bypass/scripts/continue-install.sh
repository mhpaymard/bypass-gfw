#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
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
echo "🔄 Continuing Advanced GFW Bypass Installation"
echo "=========================================="

# Get domain from environment or ask user
if [[ -z "$DOMAIN_NAME" ]]; then
    echo ""
    echo "🌐 Domain Configuration"
    echo "======================"
    echo "دامنه خود را وارد کنید (یا Enter برای استفاده از IP سرور):"
    read -p "Domain: " USER_DOMAIN
    
    # Detect server IP
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
    
    # Set domain name
    if [[ -z "$USER_DOMAIN" ]]; then
        DOMAIN_NAME="$SERVER_IP"
        print_info "استفاده از IP سرور: $DOMAIN_NAME"
    else
        DOMAIN_NAME="$USER_DOMAIN"
        print_info "استفاده از دامنه: $DOMAIN_NAME"
    fi
    
    export DOMAIN_NAME
    export SERVER_IP
fi

# Step 1: Fix V2Ray configuration
print_status "Step 1: Fixing V2Ray configuration..."

# Create v2ray user if not exists
if ! id "v2ray" &>/dev/null; then
    useradd -r -s /bin/false v2ray
    print_status "User v2ray created"
fi

# Update V2Ray config with correct domain and SSL paths
sed -i "s/your-domain.com/$DOMAIN_NAME/g" /usr/local/etc/v2ray/config.json
sed -i "s|/etc/ssl/certs/your-domain.com.crt|/etc/ssl/certs/advanced-gfw-bypass.crt|g" /usr/local/etc/v2ray/config.json
sed -i "s|/etc/ssl/private/your-domain.com.key|/etc/ssl/private/advanced-gfw-bypass.key|g" /usr/local/etc/v2ray/config.json

# Fix permissions
chown v2ray:v2ray /usr/local/etc/v2ray/config.json
chown -R v2ray:v2ray /var/log/v2ray/

# Test V2Ray config
print_status "Testing V2Ray configuration..."
if /usr/local/bin/v2ray test -c /usr/local/etc/v2ray/config.json; then
    print_success "V2Ray configuration is valid"
else
    print_error "V2Ray configuration has issues"
    exit 1
fi

# Step 2: Start all services
print_status "Step 2: Starting all services..."

# Start and enable services
systemctl daemon-reload
systemctl start v2ray
systemctl enable v2ray
systemctl start nginx
systemctl enable nginx
systemctl start redis-server
systemctl enable redis-server

# Wait for services to start
sleep 5

# Step 3: Generate client config
print_status "Step 3: Generating client configuration..."

# Extract UUID from V2Ray config
UUID=$(grep -o '"id": "[^"]*"' /usr/local/etc/v2ray/config.json | cut -d'"' -f4 | head -1)

# Create client config
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

print_success "Client configuration generated"

# Step 4: Final status check
print_status "Step 4: Final status check..."
bash system-status.sh

echo ""
echo "=========================================="
echo "🎉 Installation Complete!"
echo "=========================================="
print_success "Advanced GFW Bypass System installed successfully!"
echo ""
print_info "Server: $DOMAIN_NAME"
print_info "UUID: $UUID"
print_info "Path: /static/images/logo.png"
print_info "Client config: /root/bypass-gfw/advanced-gfw-bypass/configs/client-config.json"
echo ""
print_info "Use the client configuration to connect to your server!" 