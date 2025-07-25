# 🚀 Advanced GFW Bypass System - Quick Start Guide

## 📋 Prerequisites

Before you begin, ensure you have:

- **Server**: Ubuntu 20.04+ / CentOS 8+ / Debian 11+ (recommended)
- **Domain**: A domain name pointing to your server
- **SSL Certificate**: Let's Encrypt certificate (automatic)
- **Root Access**: Sudo privileges on the server
- **Client**: Windows/macOS/Linux with V2Ray client

## ⚡ Quick Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd advanced-gfw-bypass
```

### 2. Run the Installation Script
```bash
chmod +x scripts/install.sh
./scripts/install.sh
```

The script will automatically:
- ✅ Install all dependencies
- ✅ Configure V2Ray with advanced evasion
- ✅ Setup Nginx reverse proxy
- ✅ Install SSL certificates
- ✅ Configure firewall
- ✅ Create systemd services
- ✅ Generate client configurations

### 3. Configure Your Domain
Edit the Nginx configuration:
```bash
sudo nano /etc/nginx/sites-available/advanced-gfw-bypass
```

Replace `example.com` with your actual domain.

### 4. Get SSL Certificate
```bash
sudo certbot --nginx -d your-domain.com
```

### 5. Restart Services
```bash
sudo systemctl restart nginx v2ray
```

## 📱 Client Setup

### Windows
1. Download [V2RayN](https://github.com/2dust/v2rayN/releases)
2. Import the configuration from `/var/www/advanced-gfw-bypass/client/configs/client.json`
3. Start the service

### macOS
1. Download [V2RayU](https://github.com/yanue/V2rayU/releases)
2. Import the configuration
3. Enable the service

### Android
1. Download [V2RayNG](https://github.com/2dust/v2rayNG/releases)
2. Import the configuration
3. Connect to the server

### Linux
1. Install V2Ray client:
```bash
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
```

2. Copy the client configuration:
```bash
sudo cp /var/www/advanced-gfw-bypass/client/configs/client.json /usr/local/etc/v2ray/config.json
```

3. Start the service:
```bash
sudo systemctl start v2ray
sudo systemctl enable v2ray
```

## 🔧 Advanced Configuration

### Customizing V2Ray Configuration
```bash
cd /var/www/advanced-gfw-bypass
source venv/bin/activate
python server/v2ray/config-generator.py
```

### Monitoring System
```bash
# View real-time logs
sudo journalctl -u v2ray -f
sudo journalctl -u traffic-simulator -f

# Check system status
sudo systemctl status v2ray nginx redis
```

### Traffic Analysis
```bash
# Test connection quality
python client/tools/connection-tester.py --comprehensive

# View traffic statistics
curl http://localhost:8080/api/v1/analytics/track
```

## 🛡️ Security Features

### Automatic Evasion
- **SNI Spoofing**: Mimics popular websites
- **Domain Fronting**: Uses legitimate CDN domains
- **Traffic Simulation**: Realistic web traffic patterns
- **Protocol Hopping**: Automatic protocol switching
- **Behavioral Fingerprinting**: Mimics real user behavior

### Monitoring & Alerts
- **Real-time Monitoring**: Traffic analysis and threat detection
- **Anomaly Detection**: Statistical and behavioral analysis
- **Security Events**: Automatic threat response
- **Performance Metrics**: System health monitoring

## 🔍 Testing Your Setup

### 1. Connection Test
```bash
# Test basic connectivity
curl -I https://your-domain.com

# Test V2Ray connection
python client/tools/connection-tester.py --config client/configs/client.json
```

### 2. Traffic Simulation
```bash
# Check if traffic simulator is running
curl http://localhost:8080/

# Test API endpoints
curl http://localhost:8080/api/v1/analytics/track
```

### 3. SSL Certificate
```bash
# Verify SSL certificate
openssl s_client -connect your-domain.com:443 -servername your-domain.com
```

## 📊 Monitoring Dashboard

Access the monitoring dashboard:
```bash
# View system metrics
sudo systemctl status v2ray nginx redis traffic-simulator

# Check logs
sudo tail -f /var/log/v2ray/access.log
sudo tail -f /var/log/nginx/access.log
```

## 🔄 Maintenance

### Regular Updates
```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Update V2Ray
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# Restart services
sudo systemctl restart v2ray nginx
```

### Backup Configuration
```bash
# Backup V2Ray config
sudo cp /usr/local/etc/v2ray/config.json ~/v2ray-backup.json

# Backup Nginx config
sudo cp /etc/nginx/sites-available/advanced-gfw-bypass ~/nginx-backup.conf
```

### Troubleshooting

#### Common Issues

1. **Connection Refused**
   ```bash
   # Check if V2Ray is running
   sudo systemctl status v2ray
   
   # Check firewall
   sudo ufw status
   ```

2. **SSL Certificate Issues**
   ```bash
   # Renew certificate
   sudo certbot renew
   
   # Check certificate
   sudo certbot certificates
   ```

3. **High Latency**
   ```bash
   # Test connection quality
   python client/tools/connection-tester.py --comprehensive
   
   # Check server resources
   htop
   ```

4. **Traffic Detection**
   ```bash
   # Check logs for detection patterns
   sudo tail -f /var/log/v2ray/error.log
   
   # Rotate configuration
   cd /var/www/advanced-gfw-bypass
   source venv/bin/activate
   python server/v2ray/config-generator.py
   ```

## 🎯 Advanced Features

### Domain Rotation
The system automatically rotates domains to avoid detection:
```bash
# Check domain status
python server/domain-manager/domain-spoofer.py

# Manual rotation
# (Automatic rotation is enabled by default)
```

### Traffic Obfuscation
- **Realistic Headers**: Mimics real browser requests
- **Content Simulation**: Generates realistic web content
- **Timing Patterns**: Varies request timing
- **User Behavior**: Simulates real user sessions

### Multi-Protocol Support
- **WebSocket + TLS**: Primary protocol
- **HTTP/2**: Fallback protocol
- **gRPC**: Alternative protocol
- **QUIC/HTTP3**: Experimental protocol

## 📞 Support

### Getting Help
1. Check the logs: `sudo journalctl -u v2ray -f`
2. Test connectivity: `python client/tools/connection-tester.py`
3. Verify configuration: `sudo nginx -t`
4. Check system resources: `htop`

### Useful Commands
```bash
# Service management
sudo systemctl start|stop|restart|status v2ray
sudo systemctl start|stop|restart|status nginx

# Configuration
sudo nano /usr/local/etc/v2ray/config.json
sudo nano /etc/nginx/sites-available/advanced-gfw-bypass

# Logs
sudo tail -f /var/log/v2ray/access.log
sudo tail -f /var/log/nginx/error.log

# Monitoring
sudo systemctl status v2ray nginx redis traffic-simulator domain-manager monitoring
```

## ⚠️ Important Notes

1. **Legal Compliance**: Ensure compliance with local laws
2. **Regular Updates**: Keep the system updated
3. **Monitoring**: Monitor logs for any issues
4. **Backup**: Regularly backup configurations
5. **Security**: Use strong passwords and keep systems secure

## 🎉 Success!

Your Advanced GFW Bypass System is now running! The system provides:

- ✅ **Undetectable Traffic**: Advanced evasion techniques
- ✅ **High Performance**: Optimized for speed and reliability
- ✅ **Real-time Monitoring**: Comprehensive system monitoring
- ✅ **Automatic Maintenance**: Self-healing and rotation
- ✅ **Multi-Platform Support**: Works on all major platforms

Enjoy secure and unrestricted internet access! 🌐✨ 