# 🛠️ Advanced GFW Bypass System - Manual Setup Guide

## 📋 Overview
This guide provides step-by-step instructions for manually setting up the Advanced GFW Bypass System. This is useful when the automatic installer doesn't work or you want to understand each component.

## 🎯 Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04+, CentOS 8+, Debian 11+, or Arch Linux
- **RAM**: Minimum 2GB, Recommended 4GB+
- **Storage**: Minimum 10GB free space
- **Network**: Stable internet connection
- **Domain**: A domain name pointing to your server (optional but recommended)

### Required Software
- Python 3.8+
- Nginx
- V2Ray
- Redis
- OpenSSL
- Git

## 🚀 Step-by-Step Installation

### Step 1: System Preparation

#### Update System Packages
```bash
# Ubuntu/Debian
apt update && apt upgrade -y

# CentOS/RHEL
yum update -y

# Arch Linux
pacman -Syu --noconfirm
```

#### Install Basic Dependencies
```bash
# Ubuntu/Debian
apt install -y \
    python3 python3-pip python3-venv \
    nginx certbot python3-certbot-nginx \
    redis-server sqlite3 \
    curl wget git unzip \
    build-essential libssl-dev libffi-dev \
    ufw fail2ban \
    supervisor

# CentOS/RHEL
yum install -y \
    python3 python3-pip \
    nginx certbot python3-certbot-nginx \
    redis sqlite \
    curl wget git unzip \
    gcc openssl-devel libffi-devel \
    firewalld fail2ban \
    supervisor

# Arch Linux
pacman -S --noconfirm \
    python python-pip \
    nginx certbot certbot-nginx \
    redis sqlite \
    curl wget git unzip \
    base-devel openssl \
    ufw fail2ban \
    supervisor
```

### Step 2: Clone and Setup Project

```bash
# Clone the repository
git clone <repository-url>
cd advanced-gfw-bypass

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
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
```

### Step 3: Install V2Ray

```bash
# Download and install V2Ray
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# Create V2Ray directories
mkdir -p /usr/local/etc/v2ray
mkdir -p /var/log/v2ray
chown -R nobody:nogroup /var/log/v2ray
```

### Step 4: Configure Nginx

#### Create Nginx Configuration
```bash
cat > /etc/nginx/sites-available/advanced-gfw-bypass << 'EOF'
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

# Enable the site
ln -sf /etc/nginx/sites-available/advanced-gfw-bypass /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test configuration
nginx -t

# Reload Nginx
systemctl reload nginx
```

### Step 5: Configure SSL Certificates

#### For Testing (Self-Signed Certificate)
```bash
# Create directories
mkdir -p /etc/ssl/certs /etc/ssl/private

# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/example.com.key \
    -out /etc/ssl/certs/example.com.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com"

# Set permissions
chmod 600 /etc/ssl/private/example.com.key
chmod 644 /etc/ssl/certs/example.com.crt
```

#### For Production (Let's Encrypt)
```bash
# Install certbot
apt install -y certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d your-domain.com

# Auto-renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | crontab -
```

### Step 6: Configure Firewall

#### Ubuntu/Debian (UFW)
```bash
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 22/tcp
ufw --force enable
```

#### CentOS/RHEL (Firewalld)
```bash
systemctl start firewalld
systemctl enable firewalld
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

### Step 7: Deploy Application

```bash
# Create web directory
mkdir -p /var/www/advanced-gfw-bypass
chown -R root:root /var/www/advanced-gfw-bypass

# Copy application files
cp -r /path/to/advanced-gfw-bypass/* /var/www/advanced-gfw-bypass/

# Set permissions
chown -R www-data:www-data /var/www/advanced-gfw-bypass
chmod -R 755 /var/www/advanced-gfw-bypass

# Create static directory
mkdir -p /var/www/advanced-gfw-bypass/static
chown -R www-data:www-data /var/www/advanced-gfw-bypass/static
```

### Step 8: Generate V2Ray Configuration

```bash
cd /var/www/advanced-gfw-bypass
source venv/bin/activate

# Generate V2Ray configuration
python server/v2ray/config-generator.py

# Copy V2Ray config
cp configs/server.json /usr/local/etc/v2ray/config.json
chown nobody:nogroup /usr/local/etc/v2ray/config.json
```

### Step 9: Create Systemd Services

#### V2Ray Service
```bash
cat > /etc/systemd/system/v2ray.service << 'EOF'
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
```

#### Traffic Simulator Service
```bash
cat > /etc/systemd/system/traffic-simulator.service << 'EOF'
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
```

#### Domain Manager Service
```bash
cat > /etc/systemd/system/domain-manager.service << 'EOF'
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
```

#### Monitoring Service
```bash
cat > /etc/systemd/system/monitoring.service << 'EOF'
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
```

### Step 10: Enable and Start Services

```bash
# Reload systemd
systemctl daemon-reload

# Enable services
systemctl enable v2ray
systemctl enable traffic-simulator
systemctl enable domain-manager
systemctl enable monitoring
systemctl enable redis
systemctl enable nginx

# Start services
systemctl start redis
systemctl start nginx
systemctl start v2ray
systemctl start traffic-simulator
systemctl start domain-manager
systemctl start monitoring
```

### Step 11: Create Client Configurations

```bash
cd /var/www/advanced-gfw-bypass

# Create client configs directory
mkdir -p client/configs

# Copy client configuration
cp configs/client.json client/configs/

# Generate VMess link (optional)
python -c "
import json
import base64

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
```

## 🔧 Configuration Management

### V2Ray Configuration
- **Location**: `/usr/local/etc/v2ray/config.json`
- **Regenerate**: `python server/v2ray/config-generator.py`
- **Restart**: `systemctl restart v2ray`

### Nginx Configuration
- **Location**: `/etc/nginx/sites-available/advanced-gfw-bypass`
- **Test**: `nginx -t`
- **Reload**: `systemctl reload nginx`

### Application Configuration
- **Location**: `/var/www/advanced-gfw-bypass/`
- **Logs**: `/var/log/v2ray/`, `/var/log/nginx/`

## 📊 Monitoring and Management

### Check Service Status
```bash
# Check all services
systemctl status v2ray nginx redis traffic-simulator domain-manager monitoring

# Check specific service
systemctl status v2ray
```

### View Logs
```bash
# V2Ray logs
journalctl -u v2ray -f

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Application logs
journalctl -u traffic-simulator -f
journalctl -u domain-manager -f
journalctl -u monitoring -f
```

### Test Connections
```bash
# Test basic connectivity
curl -I https://your-domain.com

# Test V2Ray connection
python client/tools/connection-tester.py --config client/configs/client.json

# Test traffic simulator
curl http://localhost:8080/
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. V2Ray Not Starting
```bash
# Check configuration
v2ray test -c /usr/local/etc/v2ray/config.json

# Check logs
journalctl -u v2ray -f

# Check permissions
ls -la /usr/local/etc/v2ray/config.json
```

#### 2. Nginx Configuration Error
```bash
# Test configuration
nginx -t

# Check syntax
nginx -T

# Check error logs
tail -f /var/log/nginx/error.log
```

#### 3. SSL Certificate Issues
```bash
# Check certificate
openssl x509 -in /etc/ssl/certs/example.com.crt -text -noout

# Test SSL connection
openssl s_client -connect your-domain.com:443 -servername your-domain.com
```

#### 4. Firewall Issues
```bash
# Check UFW status
ufw status

# Check firewalld status
firewall-cmd --list-all

# Check open ports
netstat -tlnp
```

#### 5. Python Dependencies
```bash
# Activate virtual environment
source /var/www/advanced-gfw-bypass/venv/bin/activate

# Check installed packages
pip list

# Reinstall dependencies
pip install -r requirements.txt
```

### Performance Optimization

#### 1. System Resources
```bash
# Check system resources
htop
df -h
free -h

# Check open files
lsof | wc -l
```

#### 2. Network Optimization
```bash
# Check network interfaces
ip addr show

# Check routing
ip route show

# Test bandwidth
speedtest-cli
```

#### 3. Memory Optimization
```bash
# Check memory usage
cat /proc/meminfo

# Optimize Redis
echo "maxmemory 256mb" >> /etc/redis/redis.conf
echo "maxmemory-policy allkeys-lru" >> /etc/redis/redis.conf
systemctl restart redis
```

## 🔄 Maintenance

### Regular Updates
```bash
# Update system packages
apt update && apt upgrade -y

# Update V2Ray
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# Update application
cd /var/www/advanced-gfw-bypass
git pull
source venv/bin/activate
pip install -r requirements.txt
```

### Backup Configuration
```bash
# Backup V2Ray config
cp /usr/local/etc/v2ray/config.json ~/v2ray-backup.json

# Backup Nginx config
cp /etc/nginx/sites-available/advanced-gfw-bypass ~/nginx-backup.conf

# Backup application
tar -czf ~/advanced-gfw-bypass-backup.tar.gz /var/www/advanced-gfw-bypass/
```

### Security Updates
```bash
# Update SSL certificates
certbot renew

# Update firewall rules
ufw --force enable

# Check for security updates
apt list --upgradable
```

## 📱 Client Setup

### Windows
1. Download [V2RayN](https://github.com/2dust/v2rayN/releases)
2. Import configuration from `/var/www/advanced-gfw-bypass/client/configs/client.json`
3. Start the service

### macOS
1. Download [V2RayU](https://github.com/yanue/V2rayU/releases)
2. Import configuration
3. Enable the service

### Android
1. Download [V2RayNG](https://github.com/2dust/v2rayNG/releases)
2. Import configuration
3. Connect to the server

### Linux
```bash
# Install V2Ray client
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# Copy client configuration
cp /var/www/advanced-gfw-bypass/client/configs/client.json /usr/local/etc/v2ray/config.json

# Start the service
systemctl start v2ray
systemctl enable v2ray
```

## ⚠️ Important Notes

1. **Security**: Always use strong passwords and keep systems updated
2. **Monitoring**: Regularly check logs for any issues
3. **Backup**: Regularly backup configurations and data
4. **Legal Compliance**: Ensure compliance with local laws and regulations
5. **Performance**: Monitor system resources and optimize as needed

## 🎉 Success!

Your Advanced GFW Bypass System is now manually configured and running! The system provides:

- ✅ **Undetectable Traffic**: Advanced evasion techniques
- ✅ **High Performance**: Optimized for speed and reliability
- ✅ **Real-time Monitoring**: Comprehensive system monitoring
- ✅ **Automatic Maintenance**: Self-healing and rotation
- ✅ **Multi-Platform Support**: Works on all major platforms

Enjoy secure and unrestricted internet access! 🌐✨ 