# 🚀 راهنمای کامل سیستم v2ray با شبیه‌ساز ترافیک

## 📋 خلاصه راه‌حل

این سیستم کامل شامل:

1. **v2ray با پیکربندی ثابت** (UUID و مسیر ثابت)
2. **شبیه‌ساز ترافیک واقعی** (Python + Node.js)
3. **سیستم مدیریت کاربران** با محاسبه حجم
4. **وب‌سایت واقعی** برای پنهان‌سازی
5. **پشتیبانی از CDN و بدون CDN**
6. **مانیتورینگ کامل** و آمار

## 🎯 ویژگی‌های کلیدی

### ✅ مشکلات حل شده:
- **UUID ثابت**: برای هر کاربر یک UUID منحصر به فرد
- **مسیر ثابت**: `/api/v1/ws` برای همه کاربران
- **محاسبه حجم**: ثبت دقیق ترافیک هر کاربر
- **شبیه‌سازی کامل**: ترافیک طبیعی و غیرقابل تشخیص
- **پشتیبانی CDN**: کار با و بدون CDN

### 🔧 قابلیت‌های سیستم:
- **مدیریت کاربران**: ثبت‌نام، ورود، پروفایل
- **محاسبه ترافیک**: آپلود، دانلود، جلسات
- **پنل ادمین**: مدیریت کاربران و آمار
- **تولید پیکربندی**: خودکار برای هر کاربر
- **مانیتورینگ**: نظارت بر سیستم و ترافیک

## 🚀 نصب سریع

### مرحله 1: آماده‌سازی سرور
```bash
# به‌روزرسانی سیستم
sudo apt update && sudo apt upgrade -y

# نصب git
sudo apt install -y git

# کلون کردن پروژه
git clone https://github.com/your-repo/v2ray-traffic-simulator.git
cd v2ray-traffic-simulator
```

### مرحله 2: نصب کامل
```bash
# اجرای اسکریپت نصب
chmod +x install-complete-system.sh
sudo ./install-complete-system.sh
```

### مرحله 3: تنظیمات اولیه
اسکریپت از شما می‌خواد:
- دامنه سرور
- ایمیل برای SSL
- نام کاربری و رمز عبور ادمین
- نوع شبیه‌ساز (Python/Node.js/هر دو)

## 🔧 پیکربندی دقیق

### 1. پیکربندی v2ray (ثابت)
```json
{
  "inbounds": [{
    "port": 443,
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "UUID-ثابت-بر-اساس-دامنه",
        "alterId": 0
      }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": {
        "path": "/api/v1/ws",
        "headers": {
          "Host": "your-domain.com"
        }
      },
      "tlsSettings": {
        "serverName": "your-domain.com",
        "fingerprint": "chrome",
        "alpn": ["h2", "http/1.1"]
      }
    }
  }]
}
```

### 2. پیکربندی nginx
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # WebSocket برای v2ray
    location /api/v1/ws {
        proxy_pass http://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
    
    # وب‌سایت اصلی
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
    }
}
```

## 👥 مدیریت کاربران

### ایجاد کاربر جدید
```bash
# از طریق API
curl -X POST https://your-domain.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password123","email":"user@example.com"}'

# یا از طریق ادمین
python3 -c "
import sqlite3
import uuid
from werkzeug.security import generate_password_hash

db_path = '/var/lib/v2ray/users.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

user_uuid = str(uuid.uuid4())
password_hash = generate_password_hash('password123')

cursor.execute('''
    INSERT INTO users (username, password_hash, email, uuid)
    VALUES (?, ?, ?, ?)
''', ('user1', password_hash, 'user@example.com', user_uuid))

conn.commit()
conn.close()
print('کاربر ایجاد شد')
"
```

### تولید پیکربندی کلاینت
```bash
# تولید خودکار
/usr/local/bin/generate-client-config.sh username your-domain.com

# یا از طریق API
curl -X GET https://your-domain.com/api/user/config \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 📊 مانیتورینگ و آمار

### مشاهده آمار سیستم
```bash
# مانیتورینگ کامل
/usr/local/bin/v2ray-monitor.sh

# آمار کاربران
sqlite3 /var/lib/v2ray/users.db "SELECT COUNT(*) FROM users WHERE is_active = 1;"

# ترافیک امروز
sqlite3 /var/lib/v2ray/users.db "
SELECT 
    username,
    SUM(bytes_uploaded + bytes_downloaded) as total_traffic
FROM users u
JOIN traffic_logs t ON u.id = t.user_id
WHERE DATE(t.timestamp) = DATE('now')
GROUP BY u.id
ORDER BY total_traffic DESC;
"
```

### لاگ‌های مهم
```bash
# لاگ v2ray
tail -f /var/log/v2ray/access.log
tail -f /var/log/v2ray/error.log

# لاگ nginx
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# لاگ شبیه‌ساز
journalctl -u v2ray-traffic-simulator.service -f
journalctl -u v2ray-nodejs-simulator.service -f
```

## 🔒 نکات امنیتی

### 1. شبیه‌سازی ترافیک واقعی
- **API های متنوع**: ورود، ثبت‌نام، آپلود، دانلود، چت
- **ترافیک طبیعی**: اندازه‌های تصادفی و الگوهای واقعی
- **Headers واقعی**: User-Agent، Referer، Accept
- **الگوی زمانی**: فعالیت در ساعات مختلف

### 2. محافظت از شناسایی
- **فینگرپرینت واقعی**: Chrome، Firefox، Safari
- **ALPN مناسب**: h2، http/1.1
- **گواهی معتبر**: Let's Encrypt
- **CDN پشتیبانی**: Cloudflare، AWS CloudFront

### 3. محدودیت‌های امنیتی
- **Rate Limiting**: حداکثر 100 درخواست در 15 دقیقه
- **احراز هویت**: JWT tokens
- **فایروال**: UFW با قوانین محدود
- **HTTPS اجباری**: Redirect از HTTP

## 📱 کلاینت‌ها

### ویندوز
```json
{
  "server": "your-domain.com",
  "server_port": 443,
  "uuid": "USER-UUID-HERE",
  "alter_id": 0,
  "security": "tls",
  "network": "ws",
  "ws_opts": {
    "path": "/api/v1/ws",
    "headers": {
      "Host": "your-domain.com"
    }
  }
}
```

### اندروید (V2RayNG)
- Import از فایل JSON
- یا اسکن QR Code
- تنظیمات مشابه ویندوز

### iOS (Shadowrocket)
```
vmess://BASE64-ENCODED-CONFIG
```

## 🔄 به‌روزرسانی و نگهداری

### به‌روزرسانی خودکار
```bash
# به‌روزرسانی گواهی SSL
certbot renew

# به‌روزرسانی v2ray
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# به‌روزرسانی سیستم
apt update && apt upgrade -y
```

### پشتیبان‌گیری
```bash
# پشتیبان‌گیری از دیتابیس
cp /var/lib/v2ray/users.db /backup/users_$(date +%Y%m%d).db

# پشتیبان‌گیری از پیکربندی
cp /etc/v2ray/config.json /backup/v2ray_config_$(date +%Y%m%d).json

# پشتیبان‌گیری از گواهی‌ها
cp -r /etc/letsencrypt/live/your-domain.com /backup/certs_$(date +%Y%m%d)
```

## 🆘 عیب‌یابی

### مشکلات رایج

#### 1. اتصال قطع می‌شه
```bash
# بررسی وضعیت سرویس‌ها
systemctl status v2ray nginx

# بررسی پورت‌ها
netstat -tlnp | grep :443

# بررسی گواهی SSL
openssl s_client -connect your-domain.com:443 -servername your-domain.com
```

#### 2. سرعت پایین
```bash
# بررسی پهنای باند
speedtest-cli

# بررسی تاخیر
ping your-domain.com

# بررسی CDN
curl -I https://your-domain.com
```

#### 3. شناسایی شدن
```bash
# تغییر فینگرپرینت
sed -i 's/"fingerprint": "chrome"/"fingerprint": "firefox"/' /etc/v2ray/config.json
systemctl restart v2ray

# بررسی لاگ‌ها
tail -f /var/log/v2ray/error.log
```

### دستورات مفید
```bash
# راه‌اندازی مجدد سرویس‌ها
systemctl restart v2ray nginx

# مشاهده لاگ‌های real-time
journalctl -f -u v2ray

# تست اتصال
curl -I https://your-domain.com

# بررسی دیتابیس
sqlite3 /var/lib/v2ray/users.db ".tables"
```

## 📈 بهینه‌سازی

### 1. افزایش سرعت
- **CDN**: استفاده از Cloudflare
- **فشرده‌سازی**: gzip در nginx
- **کش**: Redis برای session ها
- **Load Balancer**: برای ترافیک بالا

### 2. افزایش امنیت
- **Fail2ban**: محافظت از brute force
- **ModSecurity**: WAF
- **IP Whitelist**: محدود کردن IP ها
- **2FA**: احراز هویت دو مرحله‌ای

### 3. افزایش پایداری
- **Monitoring**: Prometheus + Grafana
- **Backup**: پشتیبان‌گیری خودکار
- **Auto-scaling**: افزایش خودکار منابع
- **Health checks**: بررسی سلامت سرویس‌ها

## 🎯 نتیجه‌گیری

این سیستم کامل شامل:

✅ **v2ray با پیکربندی ثابت** - UUID و مسیر ثابت برای هر کاربر
✅ **شبیه‌ساز ترافیک واقعی** - ترافیک طبیعی و غیرقابل تشخیص
✅ **سیستم مدیریت کاربران** - ثبت‌نام، ورود، محاسبه حجم
✅ **وب‌سایت واقعی** - پنهان‌سازی کامل
✅ **پشتیبانی CDN** - کار با و بدون CDN
✅ **مانیتورینگ کامل** - آمار و نظارت
✅ **امنیت بالا** - محافظت از شناسایی

### نکات مهم:
1. **UUID ثابت**: هر کاربر UUID منحصر به فرد دارد
2. **مسیر ثابت**: همه از `/api/v1/ws` استفاده می‌کنند
3. **ترافیک واقعی**: شبیه‌سازی کامل وب‌سایت
4. **محاسبه حجم**: ثبت دقیق ترافیک هر کاربر
5. **پشتیبانی CDN**: انعطاف‌پذیری کامل

این سیستم به شما امکان می‌دهد تا v2ray را با امنیت بالا و قابلیت محاسبه حجم کاربران راه‌اندازی کنید، بدون اینکه نگران شناسایی شدن باشید. 