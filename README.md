# 🚀 راهنمای کامل دور زدن GFW با v2ray

این پروژه شامل ابزارها و راهنمایی‌های کامل برای راه‌اندازی v2ray با قابلیت دور زدن فیلترینگ GFW است.

## 📋 فهرست مطالب

- [مشکل اصلی](#مشکل-اصلی)
- [راه‌حل‌های پیشرفته](#راه‌حل‌های-پیشرفته)
- [نصب و راه‌اندازی](#نصب-و-راه‌اندازی)
- [پیکربندی‌های امن](#پیکربندی‌های-امن)
- [نکات امنیتی](#نکات-امنیتی)
- [عیب‌یابی](#عیب‌یابی)

## 🔍 مشکل اصلی

### چرا v2ray شناسایی می‌شه؟

1. **پروتکل‌های قابل شناسایی**
   - VMess بدون TLS به راحتی شناسایی می‌شه
   - VLESS در حالت عادی قابل تشخیصه
   - Trojan نسبتاً بهتر ولی هنوز قابل شناسایی

2. **فینگرپرینت ناقص**
   - عدم تطبیق با مرورگرهای واقعی
   - الگوی ترافیک غیرطبیعی
   - Headers نامناسب

3. **پورت‌های مشکوک**
   - استفاده از پورت‌های غیرمعمول
   - عدم تطبیق با سرویس‌های واقعی

## 🛠️ راه‌حل‌های پیشرفته

### 1. WebSocket + TLS + CDN (توصیه شده)

```json
{
  "inbounds": [{
    "port": 443,
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "your-uuid-here",
        "alterId": 0
      }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": {
        "path": "/websocket",
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

### 2. HTTP/2

```json
{
  "streamSettings": {
    "network": "h2",
    "security": "tls",
    "httpSettings": {
      "host": ["your-domain.com"],
      "path": "/api"
    }
  }
}
```

### 3. gRPC

```json
{
  "streamSettings": {
    "network": "grpc",
    "security": "tls",
    "grpcSettings": {
      "serviceName": "grpc"
    }
  }
}
```

## 🚀 نصب و راه‌اندازی

### پیش‌نیازها

- سرور Ubuntu/Debian
- دامنه با DNS تنظیم شده
- دسترسی root

### نصب خودکار

```bash
# دانلود اسکریپت
wget https://raw.githubusercontent.com/your-repo/install-v2ray-server.sh

# اجرای اسکریپت
chmod +x install-v2ray-server.sh
sudo ./install-v2ray-server.sh
```

### نصب دستی

1. **نصب v2ray**
```bash
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
```

2. **نصب nginx و certbot**
```bash
apt install -y nginx certbot python3-certbot-nginx
```

3. **تولید پیکربندی**
```bash
python3 generate-secure-config.py
```

## 🔧 پیکربندی‌های امن

### تولید پیکربندی خودکار

```bash
python3 generate-secure-config.py
```

این اسکریپت:
- UUID تصادفی تولید می‌کنه
- مسیرهای تصادفی انتخاب می‌کنه
- فینگرپرینت واقعی استفاده می‌کنه
- پیکربندی‌های مختلف تولید می‌کنه

### پیکربندی دستی

1. **انتخاب پروتکل مناسب**
   - WebSocket برای CDN
   - HTTP/2 برای سرعت بالا
   - gRPC برای پایداری

2. **تنظیم TLS**
   - استفاده از گواهی معتبر
   - فینگرپرینت مرورگر واقعی
   - ALPN مناسب

3. **تنظیم Headers**
   - Host header صحیح
   - User-Agent واقعی
   - Headers اضافی

## 🔒 نکات امنیتی

### 1. تغییرات منظم
- UUID را هر هفته تغییر دهید
- مسیرها را هر چند روز عوض کنید
- پورت‌ها را گاهی تغییر دهید

### 2. فینگرپرینت واقعی
```json
{
  "tlsSettings": {
    "fingerprint": "chrome",
    "alpn": ["h2", "http/1.1"]
  }
}
```

### 3. استفاده از CDN
- Cloudflare (رایگان)
- AWS CloudFront
- Google Cloud CDN

### 4. لاگ‌ها
```json
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  }
}
```

## 🔍 عیب‌یابی

### مشکلات رایج

1. **اتصال قطع می‌شه**
   - بررسی فایروال
   - بررسی گواهی SSL
   - بررسی DNS

2. **سرعت پایین**
   - تغییر پروتکل
   - استفاده از CDN
   - بررسی پهنای باند

3. **شناسایی شدن**
   - تغییر UUID
   - تغییر مسیر
   - استفاده از فینگرپرینت مختلف

### دستورات مفید

```bash
# بررسی وضعیت سرویس
systemctl status v2ray

# مشاهده لاگ‌ها
tail -f /var/log/v2ray/access.log

# تست اتصال
curl -I https://your-domain.com

# بررسی پورت‌ها
netstat -tlnp | grep :443
```

## 📱 کلاینت‌ها

### ویندوز
- **v2rayN**: بهترین گزینه
- **Clash for Windows**: چندپروتکلی

### اندروید
- **V2RayNG**: رسمی
- **Clash for Android**: پیشرفته

### macOS
- **V2RayX**: ساده
- **ClashX**: پیشرفته

### iOS
- **Shadowrocket**: پولی
- **Quantumult X**: پولی

## 🔄 به‌روزرسانی

### به‌روزرسانی v2ray
```bash
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
```

### به‌روزرسانی گواهی SSL
```bash
certbot renew
```

## 📞 پشتیبانی

اگر مشکلی دارید:

1. لاگ‌ها را بررسی کنید
2. پیکربندی را چک کنید
3. فایروال را بررسی کنید
4. از انجمن‌های v2ray کمک بگیرید

## ⚠️ هشدار

- این ابزارها فقط برای اهداف آموزشی هستند
- مسئولیت استفاده بر عهده کاربر است
- قوانین محلی را رعایت کنید

## 📄 لایسنس

این پروژه تحت لایسنس MIT منتشر شده است.

---

**نکته مهم**: مرتباً پیکربندی‌ها را تغییر دهید تا از شناسایی شدن جلوگیری کنید. 