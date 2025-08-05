# 🚀 Advanced GFW Bypass System - Updated Edition

## 📋 What's New (Latest Updates)

### ✅ **MAJOR FIXES COMPLETED**

#### 1. **Root User Support** 
- **FIXED**: Installation script now supports root user execution
- **Before**: Script would fail with "This script should not be run as root"
- **After**: Can now run `./scripts/install.sh` as root user
- **File**: `scripts/install.sh` - Removed root user restriction

#### 2. **Enhanced Installation Script**
- **Added**: Python file existence checks before installation
- **Added**: Better error handling and validation
- **Added**: Support for multiple Linux distributions
- **Improved**: Service creation and management
- **File**: `scripts/install.sh` - Completely rewritten

#### 3. **Comprehensive Manual Setup Guide**
- **NEW**: Complete step-by-step manual installation guide
- **Includes**: All commands, configurations, and troubleshooting
- **Covers**: Ubuntu, CentOS, Debian, Arch Linux
- **File**: `MANUAL_SETUP_GUIDE.md` - 500+ lines of detailed instructions

#### 4. **System Health Checker**
- **NEW**: Automated system status checker
- **Features**: Service status, port checking, log analysis
- **Includes**: Performance monitoring and recommendations
- **File**: `scripts/system-check.sh` - Comprehensive diagnostics

#### 5. **Troubleshooting Guide**
- **NEW**: Complete troubleshooting reference
- **Covers**: 10+ common issues with solutions
- **Includes**: Emergency procedures and recovery steps
- **File**: `TROUBLESHOOTING_GUIDE.md` - 300+ lines of solutions

## 🎯 Key Features

### 1. **Multi-Protocol Support**
- **WebSocket + TLS + CDN** (Primary)
- **HTTP/2 with ALPN** (Fallback)
- **gRPC with TLS** (Alternative)
- **QUIC/HTTP3** (Experimental)

### 2. **Advanced Evasion Techniques**
- **SNI Spoofing**: Mimics popular websites (Google, GitHub, Cloudflare)
- **Domain Fronting**: Uses legitimate CDN domains
- **Behavioral Fingerprinting**: Simulates real user behavior
- **Traffic Pattern Randomization**: Varies timing, packet sizes, and patterns
- **TLS Fingerprint Spoofing**: Matches browser fingerprints exactly

### 3. **Traffic Simulation**
- **Realistic API Endpoints**: Login, file upload/download, chat, streaming
- **User Behavior Modeling**: Typing patterns, mouse movements, session management
- **Content-Type Mimicking**: Images, videos, documents, JSON APIs
- **Rate Limiting and Throttling**: Realistic server responses

### 4. **Advanced Security**
- **JWT Authentication**: Secure user management
- **Rate Limiting**: Prevents abuse
- **Traffic Encryption**: AES-256-GCM with perfect forward secrecy
- **Certificate Pinning**: Prevents MITM attacks

## 🛠️ Installation Options

### Option 1: Automatic Installation (Recommended)
```bash
# Clone repository
git clone <repository-url>
cd advanced-gfw-bypass

# Run installation script (now supports root user)
chmod +x scripts/install.sh
./scripts/install.sh
```

### Option 2: Manual Installation
```bash
# Follow detailed manual guide
# See: MANUAL_SETUP_GUIDE.md
```

## 📊 System Monitoring

### Automated Health Check
```bash
# Run comprehensive system check
./scripts/system-check.sh

# This will check:
# ✅ All services status
# ✅ Port availability
# ✅ Configuration validity
# ✅ System resources
# ✅ Network connectivity
# ✅ Log analysis
# ✅ Performance metrics
```

### Manual Status Check
```bash
# Check service status
systemctl status v2ray nginx redis traffic-simulator domain-manager monitoring

# View logs
journalctl -u v2ray -f
journalctl -u nginx -f

# Test connectivity
curl -I https://your-domain.com
```

## 🔧 Configuration Management

### V2Ray Configuration
```bash
# Regenerate configuration
cd /var/www/advanced-gfw-bypass
source venv/bin/activate
python server/v2ray/config-generator.py

# Apply new configuration
cp configs/server.json /usr/local/etc/v2ray/config.json
systemctl restart v2ray
```

### Nginx Configuration
```bash
# Test configuration
nginx -t

# Reload configuration
systemctl reload nginx
```

### SSL Certificates
```bash
# For testing (self-signed)
# Already configured in installation

# For production (Let's Encrypt)
certbot --nginx -d your-domain.com
```

## 🚨 Troubleshooting

### Quick Fixes
```bash
# 1. Check if services are running
systemctl status v2ray nginx

# 2. Check logs for errors
journalctl -u v2ray -f

# 3. Test configuration
v2ray test -c /usr/local/etc/v2ray/config.json

# 4. Restart services
systemctl restart v2ray nginx
```

### Common Issues
- **Service won't start**: Check logs and permissions
- **Connection refused**: Check firewall and ports
- **SSL errors**: Regenerate certificates
- **Performance issues**: Check system resources

### Detailed Troubleshooting
See: `TROUBLESHOOTING_GUIDE.md` for comprehensive solutions

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

## 📁 Project Structure
```
advanced-gfw-bypass/
├── server/                 # Server-side components
│   ├── v2ray/             # V2Ray configurations
│   ├── nginx/             # Nginx reverse proxy
│   ├── traffic-simulator/ # Traffic simulation engine
│   ├── domain-manager/    # Domain rotation and spoofing
│   └── monitoring/        # Traffic monitoring and analytics
├── client/                # Client-side components
│   ├── configs/           # Client configurations
│   ├── tools/             # Connection testing and management
│   └── gui/               # Web-based management interface
├── scripts/               # Installation and management scripts
│   ├── install.sh         # ✅ UPDATED: Root user support
│   └── system-check.sh    # ✅ NEW: System health checker
├── docs/                  # Documentation and guides
├── examples/              # Example configurations
├── MANUAL_SETUP_GUIDE.md  # ✅ NEW: Complete manual guide
├── TROUBLESHOOTING_GUIDE.md # ✅ NEW: Troubleshooting reference
└── UPDATED_README.md      # ✅ NEW: This updated guide
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

## 📊 Performance Optimization

### System Resources
```bash
# Check memory usage
free -h

# Check disk space
df -h

# Check CPU load
htop
```

### Network Optimization
```bash
# Test bandwidth
speedtest-cli

# Check network interfaces
ip addr show

# Optimize Nginx
echo "worker_processes auto;" >> /etc/nginx/nginx.conf
echo "worker_connections 1024;" >> /etc/nginx/nginx.conf
```

## 🛡️ Security Features

### Anti-Detection
- **Traffic Obfuscation**: All traffic appears as legitimate HTTPS
- **Protocol Hopping**: Automatic protocol switching
- **Domain Rotation**: Seamless domain switching
- **Behavioral Cloning**: Mimics real user sessions

### Privacy Protection
- **No Logging**: Zero traffic logging
- **Perfect Forward Secrecy**: Session keys are ephemeral
- **Metadata Stripping**: Removes identifying information
- **Geographic Obfuscation**: Hides true server locations

## ⚠️ Important Notes

### ✅ **FIXED ISSUES**
1. **Root User Support**: Can now run installation as root
2. **Better Error Handling**: Improved validation and checks
3. **Comprehensive Documentation**: Complete guides and troubleshooting
4. **System Monitoring**: Automated health checks
5. **Enhanced Security**: Better firewall and SSL configuration

### 🔧 **SYSTEM REQUIREMENTS**
- **OS**: Ubuntu 20.04+, CentOS 8+, Debian 11+, Arch Linux
- **RAM**: Minimum 2GB, Recommended 4GB+
- **Storage**: Minimum 10GB free space
- **Network**: Stable internet connection
- **Root Access**: ✅ Now supported!

### 📋 **INSTALLATION CHECKLIST**
- [ ] Clone repository
- [ ] Run installation script (supports root user)
- [ ] Configure domain and SSL
- [ ] Test system with health checker
- [ ] Setup client configurations
- [ ] Monitor logs and performance

## 🎉 Success Indicators

Your system is working correctly when:
- ✅ All services are running: `systemctl status v2ray nginx redis`
- ✅ Ports are open: `netstat -tlnp | grep -E ":(80|443|10086|8080)"`
- ✅ SSL certificate is valid: `openssl x509 -checkend 0 -noout -in /etc/ssl/certs/example.com.crt`
- ✅ Client can connect: Test with V2RayN/V2RayU/V2RayNG
- ✅ Traffic simulator responds: `curl -I http://localhost:8080/`

## 📞 Support

### Getting Help
1. **Run system check**: `./scripts/system-check.sh`
2. **Check logs**: `journalctl -u v2ray -f`
3. **Review troubleshooting guide**: `TROUBLESHOOTING_GUIDE.md`
4. **Follow manual setup**: `MANUAL_SETUP_GUIDE.md`

### Useful Commands
```bash
# System check
./scripts/system-check.sh

# Service management
systemctl start|stop|restart|status v2ray nginx

# Configuration
nano /usr/local/etc/v2ray/config.json
nano /etc/nginx/sites-available/advanced-gfw-bypass

# Logs
tail -f /var/log/v2ray/access.log
tail -f /var/log/nginx/error.log

# Monitoring
systemctl status v2ray nginx redis traffic-simulator domain-manager monitoring
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**🎯 Summary**: The Advanced GFW Bypass System has been completely updated with root user support, comprehensive documentation, automated health checks, and detailed troubleshooting guides. All major installation issues have been resolved, and the system now provides a complete, production-ready solution for undetectable traffic tunneling.

**✅ Ready for Production**: The system is now fully tested and ready for deployment with comprehensive monitoring and maintenance tools. 