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

# Function to install dependencies based on OS
install_dependencies() {
    local os=$(detect_os)
    print_status "Detected OS: $os"
    
    case $os in
        "debian"|"ubuntu")
            print_status "Installing dependencies for Debian/Ubuntu..."
            sudo apt-get update
            sudo apt-get install -y \
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
            sudo yum update -y
            sudo yum install -y \
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
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm \
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
    
    # Download and install V2Ray
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    # Create V2Ray directories
    sudo mkdir -p /usr/local/etc/v2ray
    sudo mkdir -p /var/log/v2ray
    sudo chown -R nobody:nogroup /var/log/v2ray
    
    print_status "V2Ray installed"
}

# Function to configure Nginx
configure_nginx() {
    print_status "Configuring Nginx..."
    
    # Create Nginx configuration
    cat > /tmp/advanced-gfw-bypass.conf << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;
    
    # SSL configuration
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
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
    
    # Traffic simulator
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # V2Ray WebSocket path
    location /api/v1/analytics {
        proxy_pass http://127.0.0.1:10086;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Static files
    location /static/ {
        alias /var/www/advanced-gfw-bypass/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
    
    # Install configuration
    sudo cp /tmp/advanced-gfw-bypass.conf /etc/nginx/sites-available/advanced-gfw-bypass
    sudo ln -sf /etc/nginx/sites-available/advanced-gfw-bypass /etc/nginx/sites-enabled/
    
    # Remove default site
    sudo rm -f /etc/nginx/sites-enabled/default
    
    # Test configuration
    sudo nginx -t
    
    # Reload Nginx
    sudo systemctl reload nginx
    
    print_status "Nginx configured"
}

# Function to configure firewall
configure_firewall() {
    print_status "Configuring firewall..."
    
    local os=$(detect_os)
    
    case $os in
        "debian"|"ubuntu"|"arch")
            # UFW configuration
            sudo ufw --force reset
            sudo ufw default deny incoming
            sudo ufw default allow outgoing
            sudo ufw allow ssh
            sudo ufw allow 80/tcp
            sudo ufw allow 443/tcp
            sudo ufw allow 22/tcp
            sudo ufw --force enable
            ;;
        "rhel"|"centos"|"fedora")
            # Firewalld configuration
            sudo systemctl start firewalld
            sudo systemctl enable firewalld
            sudo firewall-cmd --permanent --add-service=ssh
            sudo firewall-cmd --permanent --add-service=http
            sudo firewall-cmd --permanent --add-service=https
            sudo firewall-cmd --reload
            ;;
        "macos")
            # macOS firewall (basic)
            sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
            ;;
    esac
    
    print_status "Firewall configured"
}

# Function to configure SSL certificates
configure_ssl() {
    print_status "Configuring SSL certificates..."
    
    # Create self-signed certificate for testing
    sudo mkdir -p /etc/ssl/certs /etc/ssl/private
    
    # Generate self-signed certificate
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/example.com.key \
        -out /etc/ssl/certs/example.com.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com"
    
    # Set permissions
    sudo chmod 600 /etc/ssl/private/example.com.key
    sudo chmod 644 /etc/ssl/certs/example.com.crt
    
    print_warning "Self-signed certificate created. For production, use Let's Encrypt:"
    print_warning "sudo certbot --nginx -d your-domain.com"
    
    print_status "SSL certificates configured"
}

# Function to create systemd services
create_services() {
    print_status "Creating systemd services..."
    
    # V2Ray service
    cat > /tmp/v2ray.service << 'EOF'
[Unit]
Description=V2Ray Service
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    # Traffic simulator service
    cat > /tmp/traffic-simulator.service << 'EOF'
[Unit]
Description=Advanced Traffic Simulator
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/advanced-gfw-bypass
Environment=PATH=/var/www/advanced-gfw-bypass/venv/bin
ExecStart=/var/www/advanced-gfw-bypass/venv/bin/python server/traffic-simulator/advanced-simulator.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # Domain manager service
    cat > /tmp/domain-manager.service << 'EOF'
[Unit]
Description=Advanced Domain Manager
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/advanced-gfw-bypass
Environment=PATH=/var/www/advanced-gfw-bypass/venv/bin
ExecStart=/var/www/advanced-gfw-bypass/venv/bin/python server/domain-manager/domain-spoofer.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # Monitoring service
    cat > /tmp/monitoring.service << 'EOF'
[Unit]
Description=Advanced Monitoring System
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/advanced-gfw-bypass
Environment=PATH=/var/www/advanced-gfw-bypass/venv/bin
ExecStart=/var/www/advanced-gfw-bypass/venv/bin/python server/monitoring/advanced-monitor.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # Install services
    sudo cp /tmp/v2ray.service /etc/systemd/system/
    sudo cp /tmp/traffic-simulator.service /etc/systemd/system/
    sudo cp /tmp/domain-manager.service /etc/systemd/system/
    sudo cp /tmp/monitoring.service /etc/systemd/system/
    
    # Reload systemd
    sudo systemctl daemon-reload
    
    # Enable services
    sudo systemctl enable v2ray
    sudo systemctl enable traffic-simulator
    sudo systemctl enable domain-manager
    sudo systemctl enable monitoring
    
    print_status "Systemd services created"
}

# Function to deploy application
deploy_application() {
    print_status "Deploying application..."
    
    # Create web directory
    sudo mkdir -p /var/www/advanced-gfw-bypass
    sudo chown -R $USER:$USER /var/www/advanced-gfw-bypass
    
    # Copy application files
    cp -r "$PROJECT_ROOT"/* /var/www/advanced-gfw-bypass/
    
    # Set permissions
    sudo chown -R www-data:www-data /var/www/advanced-gfw-bypass
    sudo chmod -R 755 /var/www/advanced-gfw-bypass
    
    # Create static directory
    sudo mkdir -p /var/www/advanced-gfw-bypass/static
    sudo chown -R www-data:www-data /var/www/advanced-gfw-bypass/static
    
    print_status "Application deployed"
}

# Function to generate initial configuration
generate_configuration() {
    print_status "Generating initial configuration..."
    
    cd /var/www/advanced-gfw-bypass
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Generate V2Ray configuration
    python server/v2ray/config-generator.py
    
    # Copy V2Ray config
    sudo cp configs/server.json /usr/local/etc/v2ray/config.json
    sudo chown nobody:nogroup /usr/local/etc/v2ray/config.json
    
    print_status "Configuration generated"
}

# Function to start services
start_services() {
    print_status "Starting services..."
    
    # Start Redis
    sudo systemctl start redis
    sudo systemctl enable redis
    
    # Start Nginx
    sudo systemctl start nginx
    sudo systemctl enable nginx
    
    # Start V2Ray
    sudo systemctl start v2ray
    
    # Start application services
    sudo systemctl start traffic-simulator
    sudo systemctl start domain-manager
    sudo systemctl start monitoring
    
    print_status "Services started"
}

# Function to create client configurations
create_client_configs() {
    print_status "Creating client configurations..."
    
    cd /var/www/advanced-gfw-bypass
    
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
    echo "  V2Ray: $(sudo systemctl is-active v2ray)"
    echo "  Nginx: $(sudo systemctl is-active nginx)"
    echo "  Redis: $(sudo systemctl is-active redis)"
    echo "  Traffic Simulator: $(sudo systemctl is-active traffic-simulator)"
    echo "  Domain Manager: $(sudo systemctl is-active domain-manager)"
    echo "  Monitoring: $(sudo systemctl is-active monitoring)"
    echo ""
    echo -e "${BLUE}📁 Important Files:${NC}"
    echo "  V2Ray Config: /usr/local/etc/v2ray/config.json"
    echo "  Nginx Config: /etc/nginx/sites-available/advanced-gfw-bypass"
    echo "  Application: /var/www/advanced-gfw-bypass"
    echo "  Client Configs: /var/www/advanced-gfw-bypass/client/configs/"
    echo ""
    echo -e "${BLUE}🔧 Management Commands:${NC}"
    echo "  View logs: sudo journalctl -u v2ray -f"
    echo "  Restart services: sudo systemctl restart v2ray nginx"
    echo "  Check status: sudo systemctl status v2ray"
    echo ""
    echo -e "${BLUE}📱 Client Setup:${NC}"
    echo "  Download client configs from: /var/www/advanced-gfw-bypass/client/configs/"
    echo "  Use V2RayN (Windows), V2RayU (macOS), or V2RayNG (Android)"
    echo ""
    echo -e "${YELLOW}⚠️  Important Notes:${NC}"
    echo "  - Replace example.com with your actual domain"
    echo "  - Obtain SSL certificate: sudo certbot --nginx -d your-domain.com"
    echo "  - Update firewall rules for your specific needs"
    echo "  - Monitor logs for any issues"
    echo ""
    echo -e "${GREEN}🎉 Advanced GFW Bypass System is ready!${NC}"
}

# Main installation function
main() {
    echo "Starting installation at $(date)"
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root"
        exit 1
    fi
    
    # Check if running on supported OS
    local os=$(detect_os)
    if [[ "$os" == "unknown" ]]; then
        print_error "Unsupported operating system"
        exit 1
    fi
    
    # Installation steps
    install_dependencies
    install_python_dependencies
    install_v2ray
    configure_nginx
    configure_firewall
    configure_ssl
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