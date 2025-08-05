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
echo "🌐 DNS and Domain Resolution Check"
echo "=========================================="

DOMAIN="dirdir.4doone.net"

# Step 1: Check DNS resolution
print_info "Step 1: Checking DNS resolution..."

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "Unknown")
print_info "Server IP: $SERVER_IP"

# Check domain resolution
DOMAIN_IP=$(nslookup $DOMAIN 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}')
if [[ -n "$DOMAIN_IP" ]]; then
    print_success "Domain resolves to: $DOMAIN_IP"
    
    if [[ "$DOMAIN_IP" == "$SERVER_IP" ]]; then
        print_success "Domain points to correct server IP"
    else
        print_warning "Domain IP ($DOMAIN_IP) doesn't match server IP ($SERVER_IP)"
        print_info "This might be the cause of external access issues"
    fi
else
    print_error "Domain does not resolve"
fi

# Step 2: Check from different DNS servers
print_info "Step 2: Checking from different DNS servers..."

# Google DNS
GOOGLE_IP=$(nslookup $DOMAIN 8.8.8.8 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}')
if [[ -n "$GOOGLE_IP" ]]; then
    print_info "Google DNS (8.8.8.8): $GOOGLE_IP"
else
    print_error "Google DNS cannot resolve domain"
fi

# Cloudflare DNS
CLOUDFLARE_IP=$(nslookup $DOMAIN 1.1.1.1 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}')
if [[ -n "$CLOUDFLARE_IP" ]]; then
    print_info "Cloudflare DNS (1.1.1.1): $CLOUDFLARE_IP"
else
    print_error "Cloudflare DNS cannot resolve domain"
fi

# Step 3: Check if domain is accessible from external
print_info "Step 3: Testing external accessibility..."

# Test HTTP
print_info "Testing HTTP access..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN/health 2>/dev/null)
if [[ "$HTTP_STATUS" == "200" ]]; then
    print_success "HTTP access works (Status: $HTTP_STATUS)"
elif [[ "$HTTP_STATUS" == "301" || "$HTTP_STATUS" == "302" ]]; then
    print_success "HTTP redirects to HTTPS (Status: $HTTP_STATUS)"
else
    print_error "HTTP access failed (Status: $HTTP_STATUS)"
fi

# Test HTTPS
print_info "Testing HTTPS access..."
HTTPS_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" https://$DOMAIN/health 2>/dev/null)
if [[ "$HTTPS_STATUS" == "200" ]]; then
    print_success "HTTPS access works (Status: $HTTPS_STATUS)"
else
    print_error "HTTPS access failed (Status: $HTTPS_STATUS)"
fi

# Step 4: Check SSL certificate
print_info "Step 4: Checking SSL certificate..."

SSL_INFO=$(openssl s_client -connect $DOMAIN:443 -servername $DOMAIN < /dev/null 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
if [[ -n "$SSL_INFO" ]]; then
    print_success "SSL certificate is valid"
    echo "$SSL_INFO"
else
    print_error "SSL certificate issues detected"
fi

# Step 5: Check firewall and ports
print_info "Step 5: Checking firewall and ports..."

# Check if ports are listening
if netstat -tlnp | grep -q ":443 "; then
    print_success "Port 443 is listening"
else
    print_error "Port 443 is not listening"
fi

if netstat -tlnp | grep -q ":80 "; then
    print_success "Port 80 is listening"
else
    print_error "Port 80 is not listening"
fi

# Check UFW status
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(ufw status | grep "Status: active")
    if [[ -n "$UFW_STATUS" ]]; then
        print_success "UFW firewall is active"
        print_info "Checking UFW rules for ports 80 and 443:"
        ufw status numbered | grep -E "(80|443)" || print_warning "No UFW rules found for ports 80/443"
    else
        print_warning "UFW firewall is not active"
    fi
fi

# Step 6: Recommendations
echo ""
print_info "Step 6: Recommendations:"
echo "============================"

if [[ "$DOMAIN_IP" != "$SERVER_IP" ]]; then
    print_warning "DNS ISSUE DETECTED!"
    echo "Your domain '$DOMAIN' resolves to '$DOMAIN_IP' but your server IP is '$SERVER_IP'"
    echo ""
    echo "To fix this:"
    echo "1. Go to your domain provider (4doone.net)"
    echo "2. Update DNS A record for 'dirdir.4doone.net' to point to: $SERVER_IP"
    echo "3. Wait 5-10 minutes for DNS propagation"
    echo "4. Test again with: curl -k https://dirdir.4doone.net/health"
else
    print_success "DNS is correctly configured"
fi

echo ""
print_info "Quick test commands:"
echo "======================"
echo "From your computer:"
echo "curl -k https://dirdir.4doone.net/health"
echo "curl -I https://dirdir.4doone.net"
echo ""
echo "From server:"
echo "curl -k https://dirdir.4doone.net/health"
echo "systemctl status nginx"
echo "systemctl status v2ray" 