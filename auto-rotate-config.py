#!/usr/bin/env python3
"""
اسکریپت تغییر خودکار پیکربندی v2ray
برای جلوگیری از شناسایی شدن
"""

import json
import uuid
import random
import time
import os
import sys
import subprocess
from datetime import datetime, timedelta
import schedule

class V2RayConfigRotator:
    def __init__(self, config_file="/etc/v2ray/config.json"):
        self.config_file = config_file
        self.backup_dir = "/etc/v2ray/backups"
        self.rotation_log = "/var/log/v2ray/rotation.log"
        
        # ایجاد دایرکتوری‌های مورد نیاز
        os.makedirs(self.backup_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.rotation_log), exist_ok=True)
    
    def log_message(self, message):
        """ثبت پیام در لاگ"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        with open(self.rotation_log, 'a', encoding='utf-8') as f:
            f.write(log_entry)
        
        print(f"[{timestamp}] {message}")
    
    def backup_config(self):
        """پشتیبان‌گیری از پیکربندی فعلی"""
        if os.path.exists(self.config_file):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{self.backup_dir}/config_backup_{timestamp}.json"
            
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            with open(backup_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.log_message(f"پشتیبان‌گیری از پیکربندی: {backup_file}")
            return config
        return None
    
    def generate_uuid(self):
        """تولید UUID جدید"""
        return str(uuid.uuid4())
    
    def generate_random_path(self):
        """تولید مسیر تصادفی"""
        paths = [
            "/api/v1/ws",
            "/websocket/stream",
            "/proxy/connect",
            "/cdn/static",
            "/api/rest",
            "/graphql",
            "/socket.io",
            "/live/stream",
            "/chat/ws",
            "/notification/ws",
            "/api/gateway",
            "/microservice/api",
            "/backend/ws",
            "/frontend/api",
            "/mobile/stream"
        ]
        return random.choice(paths)
    
    def generate_random_service(self):
        """تولید نام سرویس تصادفی"""
        services = [
            "grpc",
            "api",
            "service",
            "proxy",
            "stream",
            "chat",
            "live",
            "cdn",
            "api-gateway",
            "microservice",
            "backend",
            "frontend",
            "mobile",
            "web",
            "app"
        ]
        return random.choice(services)
    
    def generate_fingerprint(self):
        """تولید فینگرپرینت تصادفی"""
        fingerprints = ["chrome", "firefox", "safari", "edge", "android"]
        return random.choice(fingerprints)
    
    def rotate_websocket_config(self, domain, port=443):
        """تغییر پیکربندی WebSocket"""
        new_uuid = self.generate_uuid()
        new_path = self.generate_random_path()
        new_fingerprint = self.generate_fingerprint()
        
        config = {
            "inbounds": [{
                "port": port,
                "protocol": "vmess",
                "settings": {
                    "clients": [{
                        "id": new_uuid,
                        "alterId": 0
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {
                        "path": new_path,
                        "headers": {
                            "Host": domain
                        }
                    },
                    "tlsSettings": {
                        "serverName": domain,
                        "fingerprint": new_fingerprint,
                        "alpn": ["h2", "http/1.1"],
                        "certificates": [{
                            "certificateFile": f"/etc/v2ray/certs/{domain}.pem",
                            "keyFile": f"/etc/v2ray/certs/{domain}.key"
                        }]
                    }
                }
            }],
            "outbounds": [{
                "protocol": "freedom",
                "settings": {}
            }],
            "log": {
                "loglevel": "warning",
                "access": "/var/log/v2ray/access.log",
                "error": "/var/log/v2ray/error.log"
            }
        }
        
        return config, {
            "uuid": new_uuid,
            "path": new_path,
            "fingerprint": new_fingerprint,
            "network": "ws"
        }
    
    def rotate_h2_config(self, domain, port=443):
        """تغییر پیکربندی HTTP/2"""
        new_uuid = self.generate_uuid()
        new_path = self.generate_random_path()
        new_fingerprint = self.generate_fingerprint()
        
        config = {
            "inbounds": [{
                "port": port,
                "protocol": "vmess",
                "settings": {
                    "clients": [{
                        "id": new_uuid,
                        "alterId": 0
                    }]
                },
                "streamSettings": {
                    "network": "h2",
                    "security": "tls",
                    "httpSettings": {
                        "host": [domain],
                        "path": new_path
                    },
                    "tlsSettings": {
                        "serverName": domain,
                        "fingerprint": new_fingerprint,
                        "alpn": ["h2", "http/1.1"],
                        "certificates": [{
                            "certificateFile": f"/etc/v2ray/certs/{domain}.pem",
                            "keyFile": f"/etc/v2ray/certs/{domain}.key"
                        }]
                    }
                }
            }],
            "outbounds": [{
                "protocol": "freedom",
                "settings": {}
            }],
            "log": {
                "loglevel": "warning",
                "access": "/var/log/v2ray/access.log",
                "error": "/var/log/v2ray/error.log"
            }
        }
        
        return config, {
            "uuid": new_uuid,
            "path": new_path,
            "fingerprint": new_fingerprint,
            "network": "h2"
        }
    
    def rotate_grpc_config(self, domain, port=443):
        """تغییر پیکربندی gRPC"""
        new_uuid = self.generate_uuid()
        new_service = self.generate_random_service()
        new_fingerprint = self.generate_fingerprint()
        
        config = {
            "inbounds": [{
                "port": port,
                "protocol": "vmess",
                "settings": {
                    "clients": [{
                        "id": new_uuid,
                        "alterId": 0
                    }]
                },
                "streamSettings": {
                    "network": "grpc",
                    "security": "tls",
                    "grpcSettings": {
                        "serviceName": new_service
                    },
                    "tlsSettings": {
                        "serverName": domain,
                        "fingerprint": new_fingerprint,
                        "alpn": ["h2", "http/1.1"],
                        "certificates": [{
                            "certificateFile": f"/etc/v2ray/certs/{domain}.pem",
                            "keyFile": f"/etc/v2ray/certs/{domain}.key"
                        }]
                    }
                }
            }],
            "outbounds": [{
                "protocol": "freedom",
                "settings": {}
            }],
            "log": {
                "loglevel": "warning",
                "access": "/var/log/v2ray/access.log",
                "error": "/var/log/v2ray/error.log"
            }
        }
        
        return config, {
            "uuid": new_uuid,
            "service": new_service,
            "fingerprint": new_fingerprint,
            "network": "grpc"
        }
    
    def apply_config(self, config):
        """اعمال پیکربندی جدید"""
        try:
            # ذخیره پیکربندی جدید
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # راه‌اندازی مجدد v2ray
            subprocess.run(["systemctl", "restart", "v2ray"], check=True)
            
            self.log_message("پیکربندی جدید اعمال شد و v2ray راه‌اندازی مجدد شد")
            return True
        except Exception as e:
            self.log_message(f"خطا در اعمال پیکربندی: {e}")
            return False
    
    def rotate_config(self, domain, network_type="ws"):
        """تغییر پیکربندی"""
        self.log_message("شروع تغییر پیکربندی...")
        
        # پشتیبان‌گیری
        old_config = self.backup_config()
        
        # تولید پیکربندی جدید
        if network_type == "ws":
            new_config, info = self.rotate_websocket_config(domain)
        elif network_type == "h2":
            new_config, info = self.rotate_h2_config(domain)
        elif network_type == "grpc":
            new_config, info = self.rotate_grpc_config(domain)
        else:
            self.log_message(f"نوع شبکه نامعتبر: {network_type}")
            return False
        
        # اعمال پیکربندی
        if self.apply_config(new_config):
            self.log_message(f"پیکربندی جدید: UUID={info['uuid'][:8]}..., Path={info.get('path', info.get('service', 'N/A'))}")
            return True
        else:
            # بازگردانی پیکربندی قبلی
            if old_config:
                self.apply_config(old_config)
                self.log_message("پیکربندی قبلی بازگردانی شد")
            return False
    
    def schedule_rotation(self, domain, network_type="ws", interval_hours=24):
        """برنامه‌ریزی تغییر خودکار"""
        self.log_message(f"برنامه‌ریزی تغییر خودکار هر {interval_hours} ساعت")
        
        def job():
            self.rotate_config(domain, network_type)
        
        schedule.every(interval_hours).hours.do(job)
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # بررسی هر دقیقه
    
    def cleanup_old_backups(self, days=7):
        """پاک کردن پشتیبان‌های قدیمی"""
        cutoff_time = datetime.now() - timedelta(days=days)
        
        for filename in os.listdir(self.backup_dir):
            filepath = os.path.join(self.backup_dir, filename)
            if os.path.isfile(filepath):
                file_time = datetime.fromtimestamp(os.path.getctime(filepath))
                if file_time < cutoff_time:
                    os.remove(filepath)
                    self.log_message(f"پشتیبان قدیمی حذف شد: {filename}")

def main():
    if len(sys.argv) < 3:
        print("استفاده: python3 auto-rotate-config.py <domain> <network_type> [interval_hours]")
        print("مثال: python3 auto-rotate-config.py example.com ws 24")
        print("نوع شبکه: ws, h2, grpc")
        sys.exit(1)
    
    domain = sys.argv[1]
    network_type = sys.argv[2]
    interval_hours = int(sys.argv[3]) if len(sys.argv) > 3 else 24
    
    rotator = V2RayConfigRotator()
    
    if len(sys.argv) > 3:
        # تغییر یکباره
        rotator.rotate_config(domain, network_type)
    else:
        # تغییر خودکار
        rotator.schedule_rotation(domain, network_type, interval_hours)

if __name__ == "__main__":
    main() 