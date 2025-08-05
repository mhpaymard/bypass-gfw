#!/bin/bash

# Advanced GFW Bypass System - System Check Script
# This script checks the status of all system components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="/var/www/advanced-gfw-bypass"

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

# Function to check if service is running
check_service() {
    local service_name=$1
    local service_display_name=${2:-$service_name}
    
    if systemctl is-active --quiet $service_name; then
        print_status "$service_display_name is running"
        return 0
    else
        print_error "$service_display_name is not running"
        return 1
    fi
}

# Function to check if port is open
check_port() {
    local port=$1
    local service_name=${2:-"Service on port $port"}
    
    if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
        print_status "$service_name is listening on port $port"
        return 0
    else
        print_error "$service_name is not listening on port $port"
        return 1
    fi
}

# Function to check file exists
check_file() {
    local file_path=$1
    local description=${2:-"File $file_path"}
    
    if [[ -f "$file_path" ]]; then
        print_status "$description exists"
        return 0
    else
        print_error "$description does not exist"
        return 1
    fi
}

# Function to check directory exists
check_directory() {
    local dir_path=$1
    local description=${2:-"Directory $dir_path"}
    
    if [[ -d "$dir_path" ]]; then
        print_status "$description exists"
        return 0
    else
        print_error "$description does not exist"
        return 1
    fi
}

# Function to check Python virtual environment
check_python_env() {
    if [[ -d "$PROJECT_ROOT/venv" ]]; then
        print_status "Python virtual environment exists"
        
        # Check if venv is activated
        if [[ "$VIRTUAL_ENV" == "$PROJECT_ROOT/venv" ]]; then
            print_status "Virtual environment is activated"
        else
            print_warning "Virtual environment is not activated"
        fi
        
        # Check Python packages
        if [[ -f "$PROJECT_ROOT/venv/bin/pip" ]]; then
            print_status "pip is available in virtual environment"
        else
            print_error "pip is not available in virtual environment"
        fi
        
        return 0
    else
        print_error "Python virtual environment does not exist"
        return 1
    fi
}

# Function to check V2Ray configuration
check_v2ray_config() {
    local config_file="/usr/local/etc/v2ray/config.json"
    
    if check_file "$config_file" "V2Ray configuration file"; then
        # Test V2Ray configuration
        if v2ray test -c "$config_file" >/dev/null 2>&1; then
            print_status "V2Ray configuration is valid"
            return 0
        else
            print_error "V2Ray configuration is invalid"
            return 1
        fi
    else
        return 1
    fi
}

# Function to check Nginx configuration
check_nginx_config() {
    if nginx -t >/dev/null 2>&1; then
        print_status "Nginx configuration is valid"
        return 0
    else
        print_error "Nginx configuration is invalid"
        return 1
    fi
}

# Function to check SSL certificate
check_ssl_certificate() {
    local cert_file="/etc/ssl/certs/example.com.crt"
    local key_file="/etc/ssl/private/example.com.key"
    
    if check_file "$cert_file" "SSL certificate file" && check_file "$key_file" "SSL private key file"; then
        # Check certificate validity
        if openssl x509 -checkend 0 -noout -in "$cert_file" >/dev/null 2>&1; then
            print_status "SSL certificate is valid"
            return 0
        else
            print_error "SSL certificate is expired or invalid"
            return 1
        fi
    else
        return 1
    fi
}

# Function to check firewall status
check_firewall() {
    # Check UFW (Ubuntu/Debian)
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            print_status "UFW firewall is active"
        else
            print_warning "UFW firewall is not active"
        fi
    fi
    
    # Check firewalld (CentOS/RHEL)
    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state | grep -q "running"; then
            print_status "firewalld is active"
        else
            print_warning "firewalld is not active"
        fi
    fi
}

# Function to check system resources
check_system_resources() {
    print_info "Checking system resources..."
    
    # Check memory
    local mem_total=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    local mem_used=$(free -m | awk 'NR==2{printf "%.0f", $3}')
    local mem_percent=$((mem_used * 100 / mem_total))
    
    if [[ $mem_percent -lt 80 ]]; then
        print_status "Memory usage: ${mem_used}MB/${mem_total}MB (${mem_percent}%)"
    else
        print_warning "Memory usage: ${mem_used}MB/${mem_total}MB (${mem_percent}%) - High usage"
    fi
    
    # Check disk space
    local disk_usage=$(df -h / | awk 'NR==2{print $5}' | sed 's/%//')
    if [[ $disk_usage -lt 80 ]]; then
        print_status "Disk usage: ${disk_usage}%"
    else
        print_warning "Disk usage: ${disk_usage}% - High usage"
    fi
    
    # Check CPU load
    local cpu_load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    print_info "CPU load average: $cpu_load"
}

# Function to check network connectivity
check_network() {
    print_info "Checking network connectivity..."
    
    # Check internet connectivity
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        print_status "Internet connectivity is working"
    else
        print_error "Internet connectivity is not working"
    fi
    
    # Check DNS resolution
    if nslookup google.com >/dev/null 2>&1; then
        print_status "DNS resolution is working"
    else
        print_error "DNS resolution is not working"
    fi
}

# Function to check application logs
check_logs() {
    print_info "Checking recent logs..."
    
    # Check V2Ray logs
    if [[ -f "/var/log/v2ray/access.log" ]]; then
        local v2ray_errors=$(tail -n 50 /var/log/v2ray/access.log | grep -i error | wc -l)
        if [[ $v2ray_errors -eq 0 ]]; then
            print_status "No recent V2Ray errors found"
        else
            print_warning "Found $v2ray_errors recent V2Ray errors"
        fi
    fi
    
    # Check Nginx logs
    if [[ -f "/var/log/nginx/error.log" ]]; then
        local nginx_errors=$(tail -n 50 /var/log/nginx/error.log | grep -v "favicon.ico" | wc -l)
        if [[ $nginx_errors -eq 0 ]]; then
            print_status "No recent Nginx errors found"
        else
            print_warning "Found $nginx_errors recent Nginx errors"
        fi
    fi
}

# Function to test V2Ray connection
test_v2ray_connection() {
    print_info "Testing V2Ray connection..."
    
    # Check if V2Ray is listening on expected port
    if netstat -tlnp 2>/dev/null | grep -q ":10086 "; then
        print_status "V2Ray is listening on port 10086"
        
        # Test WebSocket connection
        if curl -s -I --http1.1 -H "Connection: Upgrade" -H "Upgrade: websocket" \
            -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: test" \
            http://localhost:10086/api/v1/analytics >/dev/null 2>&1; then
            print_status "V2Ray WebSocket endpoint is responding"
        else
            print_warning "V2Ray WebSocket endpoint is not responding"
        fi
    else
        print_error "V2Ray is not listening on port 10086"
    fi
}

# Function to test traffic simulator
test_traffic_simulator() {
    print_info "Testing traffic simulator..."
    
    # Check if traffic simulator is listening
    if netstat -tlnp 2>/dev/null | grep -q ":8080 "; then
        print_status "Traffic simulator is listening on port 8080"
        
        # Test HTTP response
        if curl -s -I http://localhost:8080/ >/dev/null 2>&1; then
            print_status "Traffic simulator is responding"
        else
            print_warning "Traffic simulator is not responding"
        fi
    else
        print_error "Traffic simulator is not listening on port 8080"
    fi
}

# Function to check client configurations
check_client_configs() {
    print_info "Checking client configurations..."
    
    local client_config_dir="$PROJECT_ROOT/client/configs"
    
    if check_directory "$client_config_dir" "Client configurations directory"; then
        local config_files=("client.json" "vmess_link.txt")
        
        for file in "${config_files[@]}"; do
            if [[ -f "$client_config_dir/$file" ]]; then
                print_status "Client configuration file $file exists"
            else
                print_warning "Client configuration file $file does not exist"
            fi
        done
    fi
}

# Function to display system information
display_system_info() {
    print_info "System Information:"
    echo "  OS: $(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "  Kernel: $(uname -r)"
    echo "  Architecture: $(uname -m)"
    echo "  Hostname: $(hostname)"
    echo "  Uptime: $(uptime -p)"
    echo ""
}

# Function to display service status summary
display_service_summary() {
    print_info "Service Status Summary:"
    
    local services=("v2ray" "nginx" "redis" "traffic-simulator" "domain-manager" "monitoring")
    local all_running=true
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            echo "  ✅ $service: Running"
        else
            echo "  ❌ $service: Not running"
            all_running=false
        fi
    done
    
    echo ""
    
    if $all_running; then
        print_status "All services are running"
    else
        print_warning "Some services are not running"
    fi
}

# Function to provide recommendations
provide_recommendations() {
    print_info "Recommendations:"
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root - consider using a non-root user for security"
    fi
    
    # Check if SSL certificate is self-signed
    if [[ -f "/etc/ssl/certs/example.com.crt" ]]; then
        print_warning "Using self-signed certificate - consider using Let's Encrypt for production"
    fi
    
    # Check if firewall is configured
    if ! command -v ufw >/dev/null 2>&1 && ! command -v firewall-cmd >/dev/null 2>&1; then
        print_warning "No firewall detected - consider configuring one"
    fi
    
    # Check if monitoring is enabled
    if ! systemctl is-active --quiet monitoring; then
        print_warning "Monitoring service is not running - consider enabling it"
    fi
}

# Main function
main() {
    echo -e "${BLUE}🔍 Advanced GFW Bypass System - System Check${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo ""
    
    # Display system information
    display_system_info
    
    # Check system resources
    check_system_resources
    echo ""
    
    # Check network connectivity
    check_network
    echo ""
    
    # Check firewall status
    check_firewall
    echo ""
    
    # Check Python environment
    check_python_env
    echo ""
    
    # Check configuration files
    print_info "Checking configuration files..."
    check_v2ray_config
    check_nginx_config
    check_ssl_certificate
    echo ""
    
    # Check directories
    print_info "Checking directories..."
    check_directory "$PROJECT_ROOT" "Application directory"
    check_directory "$PROJECT_ROOT/venv" "Python virtual environment"
    check_directory "/usr/local/etc/v2ray" "V2Ray configuration directory"
    echo ""
    
    # Check services
    print_info "Checking services..."
    check_service "v2ray" "V2Ray"
    check_service "nginx" "Nginx"
    check_service "redis" "Redis"
    check_service "traffic-simulator" "Traffic Simulator"
    check_service "domain-manager" "Domain Manager"
    check_service "monitoring" "Monitoring"
    echo ""
    
    # Check ports
    print_info "Checking ports..."
    check_port "80" "HTTP"
    check_port "443" "HTTPS"
    check_port "10086" "V2Ray"
    check_port "8080" "Traffic Simulator"
    echo ""
    
    # Test connections
    test_v2ray_connection
    echo ""
    test_traffic_simulator
    echo ""
    
    # Check client configurations
    check_client_configs
    echo ""
    
    # Check logs
    check_logs
    echo ""
    
    # Display service summary
    display_service_summary
    
    # Provide recommendations
    provide_recommendations
    echo ""
    
    print_info "System check completed!"
}

# Run main function
main "$@" 