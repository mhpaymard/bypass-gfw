#!/bin/bash

# Advanced GFW Bypass System - Installation Script
# This script installs and configures the complete undetectable bypass system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SERVER_DIR="$PROJECT_ROOT/server"
CLIENT_DIR="$PROJECT_ROOT/client"
INSTALL_DIR="/root/bypass-gfw/advanced-gfw-bypass"

# Logging
LOG_FILE="$PROJECT_ROOT/install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "${BLUE}🚀 Advanced GFW Bypass System - Installation${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "debian"
        elif command_exists yum; then
            echo "rhel"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to detect and configure domain settings
configure_domain() {
    print_status "Configuring domain settings..."
    
    # Use environment variables if set, otherwise use default
    if [[ -z "$DOMAIN_NAME" ]]; then
        # Detect server IP
        SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
        DOMAIN_NAME="$SERVER_IP"
        print_info "استفاده از IP سرور: $DOMAIN_NAME"
    else
        print_info "استفاده از دامنه تنظیم شده: $DOMAIN_NAME"
    fi
    
    # Export for other functions
    export DOMAIN_NAME
    export SERVER_IP
    
    print_status "Domain configuration completed"
}

# Function to check Python files exist
check_python_files() {
    print_status "Checking Python files..."
    
    local required_files=(
        "server/v2ray/config-generator.py"
        "server/traffic-simulator/advanced-simulator.py"
        "server/domain-manager/domain-spoofer.py"
        "server/monitoring/advanced-monitor.py"
        "client/tools/connection-tester.py"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$PROJECT_ROOT/$file" ]]; then
            print_error "Required file not found: $file"
            exit 1
        fi
    done
    
    print_status "All Python files found"
}

# Function to install dependencies based on OS
install_dependencies() {
    local os=$(detect_os)
    print_status "Detected OS: $os"
    
    case $os in
        "debian"|"ubuntu")
            print_status "Installing dependencies for Debian/Ubuntu..."
            apt-get update
            apt-get install -y \
                python3 python3-pip python3-venv \
                nginx certbot python3-certbot-nginx \
                redis-server sqlite3 \
                curl wget git unzip \
                build-essential libssl-dev libffi-dev \
                ufw fail2ban \
                supervisor
            ;;
        "rhel"|"centos"|"fedora")
            print_status "Installing dependencies for RHEL/CentOS/Fedora..."
            yum update -y
            yum install -y \
                python3 python3-pip \
                nginx certbot python3-certbot-nginx \
                redis sqlite \
                curl wget git unzip \
                gcc openssl-devel libffi-devel \
                firewalld fail2ban \
                supervisor
            ;;
        "arch")
            print_status "Installing dependencies for Arch Linux..."
            pacman -Syu --noconfirm
            pacman -S --noconfirm \
                python python-pip \
                nginx certbot certbot-nginx \
                redis sqlite \
                curl wget git unzip \
                base-devel openssl \
                ufw fail2ban \
                supervisor
            ;;
        "macos")
            print_status "Installing dependencies for macOS..."
            if ! command_exists brew; then
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install \
                python3 nginx certbot redis sqlite3 \
                curl wget git unzip \
                openssl
            ;;
        *)
            print_error "Unsupported OS: $os"
            exit 1
            ;;
    esac
}

# Function to install Python dependencies
install_python_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Create virtual environment
    python3 -m venv "$PROJECT_ROOT/venv"
    source "$PROJECT_ROOT/venv/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python packages
    pip install \
        aiohttp aiohttp-cors \
        cryptography pyjwt \
        redis dnspython \
        numpy psutil \
        requests beautifulsoup4 \
        flask flask-socketio \
        fastapi uvicorn \
        python-multipart \
        aiofiles
    
    print_status "Python dependencies installed"
}

# Function to install V2Ray
install_v2ray() {
    print_status "Installing V2Ray..."
    
    # Create v2ray user first
    if ! id "v2ray" &>/dev/null; then
        useradd -r -s /bin/false v2ray
        print_status "User v2ray created"
    fi
    
    # Download and install V2Ray
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    # Create V2Ray directories
    mkdir -p /usr/local/etc/v2ray
    mkdir -p /var/log/v2ray
    
    # Fix V2Ray service to use v2ray user instead of nobody
    sed -i 's/User=nobody/User=v2ray/g' /etc/systemd/system/v2ray.service
    
    # Set proper permissions
    chown -R v2ray:v2ray /var/log/v2ray
    chown v2ray:v2ray /usr/local/etc/v2ray/config.json 2>/dev/null || true
    
    print_status "V2Ray installed"
}

# Function to configure Nginx
configure_nginx() {
    print_status "Configuring Nginx..."
    
    # Detect server IP and domain
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
    DOMAIN_NAME=${DOMAIN_NAME:-"$SERVER_IP"}
    
    print_info "Detected server IP: $SERVER_IP"
    print_info "Using domain: $DOMAIN_NAME"
    
    # Create Nginx configuration with dynamic domain
    cat > /tmp/advanced-gfw-bypass.conf << EOF
# Advanced GFW Bypass System - Nginx Configuration
# Auto-generated configuration

# HTTP server - redirect to HTTPS
server {
    listen 80;
    server_name _;
    
    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name _;
    
    # SSL configuration - using self-signed certificate
    ssl_certificate /etc/ssl/certs/advanced-gfw-bypass.crt;
    ssl_certificate_key /etc/ssl/private/advanced-gfw-bypass.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Traffic simulator - main application
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # V2Ray WebSocket path
    location /api/v1/analytics {
        proxy_pass http://127.0.0.1:10086;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # WebSocket specific settings
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
    
    # Static files
    location /static/ {
        alias $INSTALL_DIR/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    # Status page
    location /status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
}
EOF
    
    # Install configuration
    cp /tmp/advanced-gfw-bypass.conf /etc/nginx/sites-available/advanced-gfw-bypass
    ln -sf /etc/nginx/sites-available/advanced-gfw-bypass /etc/nginx/sites-enabled/
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    # Test configuration
    if nginx -t; then
        print_status "Nginx configuration is valid"
    else
        print_error "Nginx configuration test failed"
        return 1
    fi
    
    # Start and reload Nginx
    systemctl start nginx 2>/dev/null || true
    systemctl reload nginx 2>/dev/null || true
    
    print_status "Nginx configured successfully"
}

# Function to configure firewall
configure_firewall() {
    print_status "Configuring firewall..."
    
    local os=$(detect_os)
    
    case $os in
        "debian"|"ubuntu"|"arch")
            # UFW configuration
            ufw --force reset
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw allow 22/tcp
            ufw --force enable
            ;;
        "rhel"|"centos"|"fedora")
            # Firewalld configuration
            systemctl start firewalld
            systemctl enable firewalld
            firewall-cmd --permanent --add-service=ssh
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            firewall-cmd --reload
            ;;
        "macos")
            # macOS firewall (basic)
            /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
            ;;
    esac
    
    print_status "Firewall configured"
}

# Function to configure SSL certificates
configure_ssl() {
    print_status "Configuring SSL certificates..."
    
    # Detect server IP and domain
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
    DOMAIN_NAME=${DOMAIN_NAME:-"$SERVER_IP"}
    
    # Create directories
    mkdir -p /etc/ssl/certs /etc/ssl/private
    
    # Generate self-signed certificate with proper domain
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/advanced-gfw-bypass.key \
        -out /etc/ssl/certs/advanced-gfw-bypass.crt \
        -subj "/C=US/ST=State/L=City/O=Advanced GFW Bypass/CN=$DOMAIN_NAME" \
        -addext "subjectAltName = DNS:$DOMAIN_NAME,IP:$SERVER_IP,IP:127.0.0.1"
    
    # Set permissions
    chmod 600 /etc/ssl/private/advanced-gfw-bypass.key
    chmod 644 /etc/ssl/certs/advanced-gfw-bypass.crt
    
    print_status "SSL certificate generated for domain: $DOMAIN_NAME"
    print_warning "Self-signed certificate created. For production, use Let's Encrypt:"
    print_warning "certbot --nginx -d your-domain.com"
    
    print_status "SSL certificates configured"
}

# Function to create systemd services
create_services() {
    print_status "Creating systemd services..."
    
    # Create v2ray user
    if ! id "v2ray" &>/dev/null; then
        useradd -r -s /bin/false v2ray
        print_status "User v2ray created"
    fi
    
    # V2Ray service
    cat > /tmp/v2ray.service << 'EOF'
[Unit]
Description=V2Ray Service
After=network.target

[Service]
Type=simple
User=v2ray
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    # Traffic simulator service
    cat > /tmp/traffic-simulator.service << EOF
[Unit]
Description=Advanced Traffic Simulator
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/python server/traffic-simulator/advanced-simulator.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # Domain manager service
    cat > /tmp/domain-manager.service << EOF
[Unit]
Description=Advanced Domain Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/python server/domain-manager/domain-spoofer.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # Monitoring service
    cat > /tmp/monitoring.service << EOF
[Unit]
Description=Advanced Monitoring System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/python server/monitoring/advanced-monitor.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # Install services
    cp /tmp/v2ray.service /etc/systemd/system/
    cp /tmp/traffic-simulator.service /etc/systemd/system/
    cp /tmp/domain-manager.service /etc/systemd/system/
    cp /tmp/monitoring.service /etc/systemd/system/
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable services
    systemctl enable v2ray
    systemctl enable traffic-simulator
    systemctl enable domain-manager
    systemctl enable monitoring
    
    print_status "Systemd services created"
}

# Function to deploy application
deploy_application() {
    print_status "Deploying application..."
    
    # Create web directory
    mkdir -p "$INSTALL_DIR"
    chown -R root:root "$INSTALL_DIR"
    
    # Copy application files
    cp -r "$PROJECT_ROOT"/* "$INSTALL_DIR/"
    
    # Set permissions
    chown -R root:root "$INSTALL_DIR"
    chmod -R 755 "$INSTALL_DIR"
    
    # Create static directory
    mkdir -p "$INSTALL_DIR/static"
    chown -R root:root "$INSTALL_DIR/static"
    
    print_status "Application deployed"
}

# Function to generate initial configuration
generate_configuration() {
    print_status "Generating initial configuration..."
    
    cd "$INSTALL_DIR"
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Generate V2Ray configuration
    python server/v2ray/config-generator.py
    
    # Copy V2Ray config
    cp configs/server.json /usr/local/etc/v2ray/config.json
    chown v2ray:v2ray /usr/local/etc/v2ray/config.json
    
    # Update V2Ray config with correct domain and SSL paths
    sed -i "s/your-domain.com/$DOMAIN_NAME/g" /usr/local/etc/v2ray/config.json
    sed -i "s|/etc/ssl/certs/your-domain.com.crt|/etc/ssl/certs/advanced-gfw-bypass.crt|g" /usr/local/etc/v2ray/config.json
    sed -i "s|/etc/ssl/private/your-domain.com.key|/etc/ssl/private/advanced-gfw-bypass.key|g" /usr/local/etc/v2ray/config.json
    
    print_status "Configuration generated"
}

# Function to start services
start_services() {
    print_status "Starting services..."
    
    # Start Redis
    systemctl start redis
    systemctl enable redis
    
    # Start Nginx
    systemctl start nginx
    systemctl enable nginx
    
    # Start V2Ray
    systemctl start v2ray
    
    # Start application services
    systemctl start traffic-simulator
    systemctl start domain-manager
    systemctl start monitoring
    
    print_status "Services started"
}

# Function to create client configurations
create_client_configs() {
    print_status "Creating client configurations..."
    
    cd "$INSTALL_DIR"
    
    # Create client configs directory
    mkdir -p client/configs
    
    # Copy client configuration
    cp configs/client.json client/configs/
    
    # Create QR code for mobile clients
    if command_exists qrencode; then
        # Generate VMess link
        python -c "
import json
import base64
import uuid

with open('configs/client.json', 'r') as f:
    config = json.load(f)

outbound = config['outbounds'][0]
settings = outbound['settings']['vnext'][0]
user = settings['users'][0]

vmess_config = {
    'v': '2',
    'ps': 'Advanced GFW Bypass',
    'add': settings['address'],
    'port': settings['port'],
    'id': user['id'],
    'aid': user['alterId'],
    'net': outbound['streamSettings']['network'],
    'type': 'none',
    'host': outbound['streamSettings'].get('wsSettings', {}).get('headers', {}).get('Host', ''),
    'path': outbound['streamSettings'].get('wsSettings', {}).get('path', ''),
    'tls': outbound['streamSettings']['security']
}

vmess_str = json.dumps(vmess_config)
vmess_encoded = base64.b64encode(vmess_str.encode()).decode()
vmess_link = f'vmess://{vmess_encoded}'

print(vmess_link)
" > client/configs/vmess_link.txt
        
        # Generate QR code
        qrencode -t PNG -o client/configs/vmess_qr.png < client/configs/vmess_link.txt
    fi
    
    print_status "Client configurations created"
}

# Function to display status
display_status() {
    print_status "Installation completed!"
    echo ""
    echo -e "${BLUE}📊 System Status:${NC}"
    echo "  V2Ray: $(systemctl is-active v2ray)"
    echo "  Nginx: $(systemctl is-active nginx)"
    echo "  Redis: $(systemctl is-active redis)"
    echo "  Traffic Simulator: $(systemctl is-active traffic-simulator)"
    echo "  Domain Manager: $(systemctl is-active domain-manager)"
    echo "  Monitoring: $(systemctl is-active monitoring)"
    echo ""
    echo -e "${BLUE}🌐 Domain Information:${NC}"
    echo "  Server IP: $SERVER_IP"
    echo "  Domain: $DOMAIN_NAME"
    echo "  SSL Certificate: /etc/ssl/certs/advanced-gfw-bypass.crt"
    echo ""
    echo -e "${BLUE}📁 Important Files:${NC}"
    echo "  V2Ray Config: /usr/local/etc/v2ray/config.json"
    echo "  Nginx Config: /etc/nginx/sites-available/advanced-gfw-bypass"
    echo "  Application: $INSTALL_DIR"
    echo "  Client Configs: $INSTALL_DIR/client/configs/"
    echo ""
    echo -e "${BLUE}🔧 Management Commands:${NC}"
    echo "  View logs: journalctl -u v2ray -f"
    echo "  Restart services: systemctl restart v2ray nginx"
    echo "  Check status: systemctl status v2ray"
    echo "  Test Nginx: nginx -t"
    echo ""
    echo -e "${BLUE}📱 Client Setup:${NC}"
    echo "  Download client configs from: $INSTALL_DIR/client/configs/"
    echo "  Use V2RayN (Windows), V2RayU (macOS), or V2RayNG (Android)"
    echo ""
    echo -e "${BLUE}🌐 Access URLs:${NC}"
    echo "  HTTPS: https://$DOMAIN_NAME"
    echo "  Health Check: https://$DOMAIN_NAME/health"
    echo "  Status Page: https://$DOMAIN_NAME/status"
    echo ""
    echo -e "${YELLOW}⚠️  Important Notes:${NC}"
    echo "  - SSL certificate is self-signed (for testing)"
    echo "  - For production, use Let's Encrypt: certbot --nginx -d your-domain.com"
    echo "  - Update firewall rules for your specific needs"
    echo "  - Monitor logs for any issues"
    echo ""
    echo -e "${GREEN}🎉 Advanced GFW Bypass System is ready!${NC}"
}

# Main installation function
main() {
    echo "Starting installation at $(date)"
    
    # Check if running on supported OS
    local os=$(detect_os)
    if [[ "$os" == "unknown" ]]; then
        print_error "Unsupported operating system"
        exit 1
    fi
    
    # Check Python files exist
    check_python_files
    
    # Configure domain settings first
    configure_domain
    
    # Installation steps
    install_dependencies
    install_python_dependencies
    install_v2ray
    configure_ssl
    configure_nginx
    configure_firewall
    create_services
    deploy_application
    generate_configuration
    start_services
    create_client_configs
    display_status
    
    echo "Installation completed at $(date)"
}

# Run main function
main "$@" 