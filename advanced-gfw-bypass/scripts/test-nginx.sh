#!/bin/bash

# Advanced GFW Bypass System - Nginx Test Script
# This script tests Nginx configuration and SSL certificates

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Function to test Nginx configuration
test_nginx_config() {
    print_info "Testing Nginx configuration..."
    
    if nginx -t >/dev/null 2>&1; then
        print_status "Nginx configuration is valid"
        return 0
    else
        print_error "Nginx configuration test failed"
        nginx -t
        return 1
    fi
}

# Function to test SSL certificate
test_ssl_certificate() {
    print_info "Testing SSL certificate..."
    
    local cert_file="/etc/ssl/certs/advanced-gfw-bypass.crt"
    local key_file="/etc/ssl/private/advanced-gfw-bypass.key"
    
    if [[ ! -f "$cert_file" ]]; then
        print_error "SSL certificate file not found: $cert_file"
        return 1
    fi
    
    if [[ ! -f "$key_file" ]]; then
        print_error "SSL private key file not found: $key_file"
        return 1
    fi
    
    # Check certificate validity
    if openssl x509 -checkend 0 -noout -in "$cert_file" >/dev/null 2>&1; then
        print_status "SSL certificate is valid"
    else
        print_error "SSL certificate is expired or invalid"
        return 1
    fi
    
    # Check certificate details
    print_info "Certificate details:"
    openssl x509 -in "$cert_file" -text -noout | grep -E "(Subject:|DNS:|IP Address:)"
    
    return 0
}

# Function to test Nginx service
test_nginx_service() {
    print_info "Testing Nginx service..."
    
    if systemctl is-active --quiet nginx; then
        print_status "Nginx service is running"
    else
        print_error "Nginx service is not running"
        return 1
    fi
    
    # Check if Nginx is listening on ports
    if netstat -tlnp 2>/dev/null | grep -q ":80 "; then
        print_status "Nginx is listening on port 80"
    else
        print_error "Nginx is not listening on port 80"
    fi
    
    if netstat -tlnp 2>/dev/null | grep -q ":443 "; then
        print_status "Nginx is listening on port 443"
    else
        print_error "Nginx is not listening on port 443"
    fi
    
    return 0
}

# Function to test HTTP connectivity
test_http_connectivity() {
    print_info "Testing HTTP connectivity..."
    
    # Get server IP
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
    
    # Test HTTP response
    if curl -s -I http://$server_ip/ >/dev/null 2>&1; then
        print_status "HTTP connectivity is working"
        return 0
    else
        print_error "HTTP connectivity failed"
        return 1
    fi
}

# Function to test HTTPS connectivity
test_https_connectivity() {
    print_info "Testing HTTPS connectivity..."
    
    # Get server IP
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
    
    # Test HTTPS response (ignore SSL certificate warnings for self-signed)
    if curl -s -I -k https://$server_ip/ >/dev/null 2>&1; then
        print_status "HTTPS connectivity is working"
        return 0
    else
        print_error "HTTPS connectivity failed"
        return 1
    fi
}

# Function to test specific endpoints
test_endpoints() {
    print_info "Testing specific endpoints..."
    
    # Get server IP
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
    
    # Test health endpoint
    if curl -s -k https://$server_ip/health >/dev/null 2>&1; then
        print_status "Health endpoint is working"
    else
        print_warning "Health endpoint is not responding"
    fi
    
    # Test status endpoint
    if curl -s -k https://$server_ip/status >/dev/null 2>&1; then
        print_status "Status endpoint is working"
    else
        print_warning "Status endpoint is not responding"
    fi
}

# Function to check Nginx logs
check_nginx_logs() {
    print_info "Checking recent Nginx logs..."
    
    if [[ -f "/var/log/nginx/error.log" ]]; then
        local error_count=$(tail -n 50 /var/log/nginx/error.log | grep -v "favicon.ico" | wc -l)
        if [[ $error_count -eq 0 ]]; then
            print_status "No recent Nginx errors found"
        else
            print_warning "Found $error_count recent Nginx errors"
            echo "Recent errors:"
            tail -n 10 /var/log/nginx/error.log | grep -v "favicon.ico"
        fi
    else
        print_warning "Nginx error log not found"
    fi
}

# Function to display configuration summary
display_config_summary() {
    print_info "Nginx Configuration Summary:"
    echo ""
    echo "Configuration file: /etc/nginx/sites-available/advanced-gfw-bypass"
    echo "SSL Certificate: /etc/ssl/certs/advanced-gfw-bypass.crt"
    echo "SSL Private Key: /etc/ssl/private/advanced-gfw-bypass.key"
    echo ""
    
    # Show server IP
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
    echo "Server IP: $server_ip"
    echo "Access URLs:"
    echo "  HTTP: http://$server_ip"
    echo "  HTTPS: https://$server_ip"
    echo "  Health: https://$server_ip/health"
    echo "  Status: https://$server_ip/status"
    echo ""
}

# Main function
main() {
    echo -e "${BLUE}🔍 Advanced GFW Bypass System - Nginx Test${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo ""
    
    # Test Nginx configuration
    test_nginx_config
    echo ""
    
    # Test SSL certificate
    test_ssl_certificate
    echo ""
    
    # Test Nginx service
    test_nginx_service
    echo ""
    
    # Test connectivity
    test_http_connectivity
    echo ""
    test_https_connectivity
    echo ""
    
    # Test endpoints
    test_endpoints
    echo ""
    
    # Check logs
    check_nginx_logs
    echo ""
    
    # Display summary
    display_config_summary
    
    print_info "Nginx test completed!"
}

# Run main function
main "$@" 