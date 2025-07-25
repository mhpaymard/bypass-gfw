# 🚀 راهنمای سریع شروع

## مشکل شما چیست؟

اگر v2ray شما توسط GFW شناسایی می‌شه، احتمالاً به یکی از این دلایل است:

1. **پروتکل ساده**: VMess بدون TLS
2. **فینگرپرینت ناقص**: عدم تطبیق با مرورگرهای واقعی
3. **پورت مشکوک**: استفاده از پورت‌های غیرمعمول
4. **الگوی ترافیک**: قابل تشخیص بودن

## 🛠️ راه‌حل سریع (5 دقیقه)

### مرحله 1: نصب ابزارها

```bash
# نصب وابستگی‌های Python
pip3 install -r requirements.txt

# دانلود اسکریپت‌ها
chmod +x install-v2ray-server.sh
chmod +x generate-secure-config.py
chmod +x test-connection.py
chmod +x auto-rotate-config.py
```

### مرحله 2: تولید پیکربندی امن

```bash
python3 generate-secure-config.py
```

این اسکریپت از شما می‌خواد:
- دامنه سرور
- IP سرور
- پورت (443 توصیه می‌شه)

### مرحله 3: نصب سرور

```bash
sudo ./install-v2ray-server.sh
```

### مرحله 4: تست اتصال

```bash
python3 test-connection.py your-domain.com 443
```

## 🔧 پیکربندی‌های پیشنهادی

### 1. WebSocket + CDN (بهترین)

```json
{
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
```

### 2. HTTP/2 (سریع)

```json
{
  "network": "h2",
  "security": "tls",
  "httpSettings": {
    "host": ["your-domain.com"],
    "path": "/api"
  }
}
```

### 3. gRPC (پایدار)

```json
{
  "network": "grpc",
  "security": "tls",
  "grpcSettings": {
    "serviceName": "grpc"
  }
}
```

## 🔒 نکات امنیتی مهم

### 1. تغییرات منظم
```bash
# تغییر خودکار هر 24 ساعت
python3 auto-rotate-config.py your-domain.com ws 24
```

### 2. استفاده از CDN
- Cloudflare (رایگان)
- AWS CloudFront
- Google Cloud CDN

### 3. فینگرپرینت واقعی
```json
{
  "fingerprint": "chrome",
  "alpn": ["h2", "http/1.1"]
}
```

## 📱 کلاینت‌های توصیه شده

### ویندوز
- **v2rayN**: بهترین گزینه
- **Clash for Windows**: چندپروتکلی

### اندروید
- **V2RayNG**: رسمی
- **Clash for Android**: پیشرفته

### macOS
- **V2RayX**: ساده
- **ClashX**: پیشرفته

## 🔍 عیب‌یابی سریع

### مشکل: اتصال قطع می‌شه
```bash
# بررسی وضعیت سرویس
systemctl status v2ray

# مشاهده لاگ‌ها
tail -f /var/log/v2ray/error.log
```

### مشکل: سرعت پایین
```bash
# تست تاخیر
python3 test-connection.py your-domain.com

# تغییر پروتکل
python3 auto-rotate-config.py your-domain.com h2
```

### مشکل: شناسایی شدن
```bash
# تغییر فوری پیکربندی
python3 auto-rotate-config.py your-domain.com ws

# استفاده از CDN
# دامنه را در Cloudflare ثبت کنید
```

## 📊 مانیتورینگ

### لاگ‌های مهم
```bash
# لاگ دسترسی
tail -f /var/log/v2ray/access.log

# لاگ خطاها
tail -f /var/log/v2ray/error.log

# لاگ تغییرات
tail -f /var/log/v2ray/rotation.log
```

### تست منظم
```bash
# تست روزانه
python3 test-connection.py your-domain.com

# بررسی گواهی SSL
certbot certificates
```

## ⚡ بهینه‌سازی

### 1. افزایش سرعت
- استفاده از HTTP/2
- CDN نزدیک
- سرور با پهنای باند بالا

### 2. افزایش امنیت
- تغییر منظم UUID
- فینگرپرینت واقعی
- مسیرهای تصادفی

### 3. افزایش پایداری
- gRPC پروتکل
- Load balancer
- Backup سرور

## 🆘 پشتیبانی

اگر مشکلی دارید:

1. **لاگ‌ها را بررسی کنید**
2. **تست اتصال انجام دهید**
3. **پیکربندی را تغییر دهید**
4. **از انجمن‌ها کمک بگیرید**

## 📋 چک‌لیست نهایی

- [ ] دامنه با DNS تنظیم شده
- [ ] گواهی SSL نصب شده
- [ ] فایروال تنظیم شده
- [ ] CDN فعال شده
- [ ] پیکربندی امن تولید شده
- [ ] تست اتصال موفق بوده
- [ ] تغییر خودکار فعال شده
- [ ] لاگ‌ها بررسی شده

---

**نکته مهم**: همیشه از پیکربندی‌های امن استفاده کنید و مرتباً تغییر دهید! 