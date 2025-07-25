# راهنمای کامل دور زدن GFW با v2ray

## مشکل اصلی: چرا v2ray شناسایی می‌شه؟

### 1. پروتکل‌های قابل شناسایی
- **VMess**: بدون TLS به راحتی شناسایی می‌شه
- **VLESS**: در حالت عادی قابل تشخیصه
- **Trojan**: نسبتاً بهتر ولی هنوز قابل شناسایی

### 2. فینگرپرینت ناقص
- عدم تطبیق با مرورگرهای واقعی
- الگوی ترافیک غیرطبیعی
- Headers نامناسب

### 3. پورت‌های مشکوک
- استفاده از پورت‌های غیرمعمول (443، 80، 8080)
- عدم تطبیق با سرویس‌های واقعی

## راه‌حل‌های پیشرفته

### 1. استفاده از WebSocket + TLS + CDN

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
        "certificates": [{
          "certificateFile": "/path/to/cert.pem",
          "keyFile": "/path/to/key.pem"
        }]
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom"
  }]
}
```

### 2. استفاده از H2 (HTTP/2)

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

### 3. استفاده از gRPC

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

### 4. فینگرپرینت پیشرفته

```json
{
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "your-domain.com",
      "fingerprint": "chrome",
      "alpn": ["h2", "http/1.1"]
    }
  }
}
```

## بهترین پیکربندی‌ها

### 1. WebSocket + CDN (توصیه شده)
- از CDN مثل Cloudflare استفاده کنید
- پورت 443 با TLS
- مسیر WebSocket تصادفی

### 2. H2 + Real Website
- روی یک وب‌سایت واقعی نصب کنید
- از مسیرهای API واقعی استفاده کنید
- فینگرپرینت Chrome یا Firefox

### 3. gRPC + Load Balancer
- از gRPC برای ترافیک استفاده کنید
- Load balancer برای توزیع ترافیک
- مسیر سرویس تصادفی

## نکات مهم امنیتی

1. **UUID تصادفی**: از UUID تصادفی استفاده کنید
2. **مسیرهای تصادفی**: مسیر WebSocket/H2 رو تصادفی کنید
3. **فینگرپرینت واقعی**: از فینگرپرینت مرورگرهای واقعی استفاده کنید
4. **CDN**: حتماً از CDN استفاده کنید
5. **دامنه واقعی**: از دامنه‌های واقعی استفاده کنید

## تست و مانیتورینگ

1. **تست سرعت**: سرعت رو مرتب چک کنید
2. **لاگ‌ها**: لاگ‌های سرور رو بررسی کنید
3. **تست اتصال**: از ابزارهای مختلف تست کنید
4. **تغییرات**: مرتباً پیکربندی رو تغییر بدید

## ابزارهای مفید

- **v2rayN**: کلاینت ویندوز
- **V2RayNG**: کلاینت اندروید
- **Clash**: کلاینت چندپروتکلی
- **Xray**: نسخه بهبود یافته v2ray 