# 🔧 Advanced GFW Bypass System - Troubleshooting Guide

## 🚨 Common Issues and Solutions

### 1. Installation Issues

#### Problem: Script fails to run as root
**Error**: `This script should not be run as root`

**Solution**: 
- ✅ **FIXED**: The script now supports root user execution
- Run the installation script directly: `./scripts/install.sh`

#### Problem: Python dependencies installation fails
**Error**: `ModuleNotFoundError` or `pip install` fails

**Solution**:
```bash
# Check Python version
python3 --version

# Create virtual environment manually
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies one by one
pip install aiohttp
pip install cryptography
pip install redis
# ... continue with other packages
```

#### Problem: V2Ray installation fails
**Error**: V2Ray installation script fails

**Solution**:
```bash
# Manual V2Ray installation
curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh -o install-v2ray.sh
bash install-v2ray.sh

# Or download and install manually
wget https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-linux-64.zip
unzip v2ray-linux-64.zip
sudo mv v2ray /usr/local/bin/
sudo chmod +x /usr/local/bin/v2ray
```

### 2. Service Issues

#### Problem: Nginx service won't start
**Error**: `nginx: configuration test failed`

**Solution**:
```bash
# Test Nginx configuration
nginx -t

# Check configuration syntax
nginx -T

# Check error logs
tail -f /var/log/nginx/error.log

# Fix common issues
sudo mkdir -p /var/log/nginx
sudo chown www-data:www-data /var/log/nginx
```

#### Problem: Nginx SSL certificate errors
**Error**: `SSL certificate not found` or `SSL certificate invalid`

**Solution**:
```bash
# Check if certificate files exist
ls -la /etc/ssl/certs/advanced-gfw-bypass.crt
ls -la /etc/ssl/private/advanced-gfw-bypass.key

# Regenerate SSL certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/advanced-gfw-bypass.key \
    -out /etc/ssl/certs/advanced-gfw-bypass.crt \
    -subj "/C=US/ST=State/L=City/O=Advanced GFW Bypass/CN=$(curl -s ifconfig.me)" \
    -addext "subjectAltName = DNS:$(curl -s ifconfig.me),IP:$(curl -s ifconfig.me),IP:127.0.0.1"

# Set permissions
chmod 600 /etc/ssl/private/advanced-gfw-bypass.key
chmod 644 /etc/ssl/certs/advanced-gfw-bypass.crt

# Test Nginx configuration
nginx -t

# Reload Nginx
systemctl reload nginx
```

#### Problem: Nginx domain configuration issues
**Error**: `server_name` or domain not working

**Solution**:
```bash
# Check current domain configuration
grep -r "server_name" /etc/nginx/sites-available/

# Update domain in Nginx config
sed -i 's/example\.com/your-actual-domain.com/g' /etc/nginx/sites-available/advanced-gfw-bypass

# Test and reload
nginx -t && systemctl reload nginx
```

#### Problem: Nginx proxy errors
**Error**: `502 Bad Gateway` or proxy connection refused

**Solution**:
```bash
# Check if backend services are running
systemctl status traffic-simulator
systemctl status v2ray

# Check backend ports
netstat -tlnp | grep :8080
netstat -tlnp | grep :10086

# Restart backend services
systemctl restart traffic-simulator
systemctl restart v2ray

# Check Nginx logs
tail -f /var/log/nginx/error.log
```

#### Problem: V2Ray service won't start
**Error**: `Failed to start v2ray.service`

**Solution**:
```bash
# Check V2Ray configuration
v2ray test -c /usr/local/etc/v2ray/config.json

# Check logs
journalctl -u v2ray -f

# Check permissions
ls -la /usr/local/etc/v2ray/config.json
sudo chown nobody:nogroup /usr/local/etc/v2ray/config.json

# Restart service
systemctl restart v2ray
```

#### Problem: Traffic simulator not responding
**Error**: Connection refused on port 8080

**Solution**:
```bash
# Check if service is running
systemctl status traffic-simulator

# Check logs
journalctl -u traffic-simulator -f

# Restart service
systemctl restart traffic-simulator

# Check Python environment
cd /var/www/advanced-gfw-bypass
source venv/bin/activate
python server/traffic-simulator/advanced-simulator.py
```

### 3. Network Issues

#### Problem: Port 80/443 not accessible
**Error**: Connection refused

**Solution**:
```bash
# Check if ports are open
netstat -tlnp | grep :80
netstat -tlnp | grep :443

# Check firewall
ufw status
firewall-cmd --list-all

# Open ports
ufw allow 80/tcp
ufw allow 443/tcp
```

#### Problem: SSL certificate issues
**Error**: SSL certificate errors

**Solution**:
```bash
# Check certificate
openssl x509 -in /etc/ssl/certs/example.com.crt -text -noout

# Generate new self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/example.com.key \
    -out /etc/ssl/certs/example.com.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com"

# Set permissions
chmod 600 /etc/ssl/private/example.com.key
chmod 644 /etc/ssl/certs/example.com.crt
```

#### Problem: DNS resolution issues
**Error**: Cannot resolve domain names

**Solution**:
```bash
# Check DNS configuration
cat /etc/resolv.conf

# Test DNS resolution
nslookup google.com

# Use alternative DNS
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf
```

### 4. Configuration Issues

#### Problem: V2Ray configuration invalid
**Error**: `Invalid configuration`

**Solution**:
```bash
# Regenerate configuration
cd /var/www/advanced-gfw-bypass
source venv/bin/activate
python server/v2ray/config-generator.py

# Copy new configuration
cp configs/server.json /usr/local/etc/v2ray/config.json
chown nobody:nogroup /usr/local/etc/v2ray/config.json

# Restart V2Ray
systemctl restart v2ray
```

#### Problem: Client configuration not working
**Error**: Client cannot connect

**Solution**:
```bash
# Check server configuration
cat /usr/local/etc/v2ray/config.json

# Generate new client config
cd /var/www/advanced-gfw-bypass
source venv/bin/activate
python server/v2ray/config-generator.py

# Copy client config
cp configs/client.json client/configs/
```

### 5. Performance Issues

#### Problem: High memory usage
**Error**: System running out of memory

**Solution**:
```bash
# Check memory usage
free -h
htop

# Optimize Redis
echo "maxmemory 256mb" >> /etc/redis/redis.conf
echo "maxmemory-policy allkeys-lru" >> /etc/redis/redis.conf
systemctl restart redis

# Restart services
systemctl restart v2ray nginx
```

#### Problem: High CPU usage
**Error**: System overloaded

**Solution**:
```bash
# Check CPU usage
top
htop

# Check which processes are using CPU
ps aux --sort=-%cpu | head -10

# Restart heavy services
systemctl restart traffic-simulator
systemctl restart monitoring
```

#### Problem: Slow connection speeds
**Error**: Poor performance

**Solution**:
```bash
# Check network speed
speedtest-cli

# Optimize Nginx
echo "worker_processes auto;" >> /etc/nginx/nginx.conf
echo "worker_connections 1024;" >> /etc/nginx/nginx.conf

# Restart Nginx
systemctl restart nginx
```

### 6. Security Issues

#### Problem: Firewall blocking connections
**Error**: Connection refused

**Solution**:
```bash
# Check firewall status
ufw status
firewall-cmd --list-all

# Allow necessary ports
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 10086/tcp
ufw allow 8080/tcp

# Reload firewall
ufw reload
```

#### Problem: SSL certificate warnings
**Error**: Certificate not trusted

**Solution**:
```bash
# For production, use Let's Encrypt
apt install -y certbot python3-certbot-nginx
certbot --nginx -d your-domain.com

# For testing, accept self-signed certificate
# Add exception in browser or client
```

### 7. Log Analysis

#### Check V2Ray logs
```bash
# View real-time logs
journalctl -u v2ray -f

# Check access logs
tail -f /var/log/v2ray/access.log

# Check error logs
tail -f /var/log/v2ray/error.log
```

#### Check Nginx logs
```bash
# View access logs
tail -f /var/log/nginx/access.log

# View error logs
tail -f /var/log/nginx/error.log

# Check specific errors
grep -i error /var/log/nginx/error.log
```

#### Check application logs
```bash
# Traffic simulator logs
journalctl -u traffic-simulator -f

# Domain manager logs
journalctl -u domain-manager -f

# Monitoring logs
journalctl -u monitoring -f
```

### 8. System Recovery

#### Complete system reset
```bash
# Stop all services
systemctl stop v2ray nginx redis traffic-simulator domain-manager monitoring

# Remove configurations
rm -rf /usr/local/etc/v2ray/config.json
rm -rf /etc/nginx/sites-enabled/advanced-gfw-bypass

# Reinstall from scratch
cd /var/www/advanced-gfw-bypass
./scripts/install.sh
```

#### Backup and restore
```bash
# Create backup
tar -czf ~/advanced-gfw-bypass-backup-$(date +%Y%m%d).tar.gz \
    /usr/local/etc/v2ray/config.json \
    /etc/nginx/sites-available/advanced-gfw-bypass \
    /var/www/advanced-gfw-bypass/

# Restore from backup
tar -xzf ~/advanced-gfw-bypass-backup-YYYYMMDD.tar.gz -C /
```

### 9. Client-Side Issues

#### Windows client issues
```bash
# Check V2RayN configuration
# Import correct client.json file
# Check Windows Firewall
# Run as administrator if needed
```

#### Android client issues
```bash
# Check V2RayNG configuration
# Import VMess link or QR code
# Check Android network settings
# Clear app data and reconfigure
```

#### Linux client issues
```bash
# Check V2Ray client installation
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# Copy client configuration
cp /var/www/advanced-gfw-bypass/client/configs/client.json /usr/local/etc/v2ray/config.json

# Start client service
systemctl start v2ray
systemctl enable v2ray
```

### 10. Advanced Debugging

#### Network debugging
```bash
# Check network interfaces
ip addr show

# Check routing
ip route show

# Test connectivity
ping -c 4 8.8.8.8
curl -I https://google.com

# Check DNS
nslookup google.com
dig google.com
```

#### System debugging
```bash
# Check system resources
htop
df -h
free -h

# Check open files
lsof | wc -l
lsof -p $(pgrep v2ray)

# Check system limits
ulimit -a
```

#### Service debugging
```bash
# Check service dependencies
systemctl list-dependencies v2ray

# Check service logs
journalctl -u v2ray --since "1 hour ago"

# Check service status
systemctl status v2ray --no-pager -l
```

## 🆘 Emergency Procedures

### If system is completely down
```bash
# 1. Check basic connectivity
ping -c 4 8.8.8.8

# 2. Check if services are running
systemctl status v2ray nginx redis

# 3. Check logs for errors
journalctl -u v2ray -n 50

# 4. Restart critical services
systemctl restart nginx v2ray

# 5. Check firewall
ufw status
```

### If client cannot connect
```bash
# 1. Test server connectivity
curl -I https://your-domain.com

# 2. Check V2Ray is running
systemctl status v2ray

# 3. Check port is open
netstat -tlnp | grep 10086

# 4. Regenerate client config
cd /var/www/advanced-gfw-bypass
source venv/bin/activate
python server/v2ray/config-generator.py
```

### If performance is poor
```bash
# 1. Check system resources
htop

# 2. Restart services
systemctl restart v2ray nginx redis

# 3. Check for errors
journalctl -u v2ray --since "10 minutes ago"

# 4. Optimize configuration
# Edit /usr/local/etc/v2ray/config.json
```

## 📞 Getting Help

### Before asking for help, please provide:
1. **System information**: OS version, architecture
2. **Error messages**: Exact error text
3. **Logs**: Relevant log entries
4. **Steps to reproduce**: What you did before the error
5. **System check output**: Run `./scripts/system-check.sh`

### Useful commands for diagnostics:
```bash
# System check
./scripts/system-check.sh

# Service status
systemctl status v2ray nginx redis traffic-simulator domain-manager monitoring

# Recent logs
journalctl -u v2ray --since "1 hour ago"

# Network test
curl -I https://your-domain.com
```

## ⚠️ Important Notes

1. **Always backup** before making changes
2. **Check logs** before asking for help
3. **Test changes** in a safe environment first
4. **Keep system updated** regularly
5. **Monitor performance** continuously

## 🎯 Quick Fix Checklist

- [ ] Check if services are running: `systemctl status v2ray nginx`
- [ ] Check logs for errors: `journalctl -u v2ray -f`
- [ ] Test configuration: `v2ray test -c /usr/local/etc/v2ray/config.json`
- [ ] Check firewall: `ufw status`
- [ ] Test connectivity: `curl -I https://your-domain.com`
- [ ] Regenerate config if needed: `python server/v2ray/config-generator.py`
- [ ] Restart services: `systemctl restart v2ray nginx`

---

**Remember**: Most issues can be resolved by checking logs and restarting services. If problems persist, use the system check script for comprehensive diagnostics. 