#!/usr/bin/env python3
"""
اسکریپت تولید پیکربندی امن v2ray
برای دور زدن GFW
"""

import json
import uuid
import random
import string
import os
from datetime import datetime

def generate_uuid():
    """تولید UUID تصادفی"""
    return str(uuid.uuid4())

def generate_random_path():
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
        "/notification/ws"
    ]
    return random.choice(paths)

def generate_random_service_name():
    """تولید نام سرویس تصادفی برای gRPC"""
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
        "microservice"
    ]
    return random.choice(services)

def generate_websocket_config(domain, port=443):
    """تولید پیکربندی WebSocket + TLS"""
    return {
        "inbounds": [{
            "port": port,
            "protocol": "vmess",
            "settings": {
                "clients": [{
                    "id": generate_uuid(),
                    "alterId": 0
                }]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": generate_random_path(),
                    "headers": {
                        "Host": domain
                    }
                },
                "tlsSettings": {
                    "serverName": domain,
                    "fingerprint": random.choice(["chrome", "firefox", "safari"]),
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
            "loglevel": "warning"
        }
    }

def generate_h2_config(domain, port=443):
    """تولید پیکربندی HTTP/2"""
    return {
        "inbounds": [{
            "port": port,
            "protocol": "vmess",
            "settings": {
                "clients": [{
                    "id": generate_uuid(),
                    "alterId": 0
                }]
            },
            "streamSettings": {
                "network": "h2",
                "security": "tls",
                "httpSettings": {
                    "host": [domain],
                    "path": generate_random_path()
                },
                "tlsSettings": {
                    "serverName": domain,
                    "fingerprint": random.choice(["chrome", "firefox"]),
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
            "loglevel": "warning"
        }
    }

def generate_grpc_config(domain, port=443):
    """تولید پیکربندی gRPC"""
    return {
        "inbounds": [{
            "port": port,
            "protocol": "vmess",
            "settings": {
                "clients": [{
                    "id": generate_uuid(),
                    "alterId": 0
                }]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {
                    "serviceName": generate_random_service_name()
                },
                "tlsSettings": {
                    "serverName": domain,
                    "fingerprint": random.choice(["chrome", "firefox"]),
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
            "loglevel": "warning"
        }
    }

def generate_client_config(server_ip, port, uuid, path, network="ws"):
    """تولید پیکربندی کلاینت"""
    if network == "ws":
        return {
            "server": server_ip,
            "server_port": port,
            "uuid": uuid,
            "alter_id": 0,
            "security": "tls",
            "network": "ws",
            "ws_opts": {
                "path": path,
                "headers": {
                    "Host": "your-domain.com"
                }
            }
        }
    elif network == "h2":
        return {
            "server": server_ip,
            "server_port": port,
            "uuid": uuid,
            "alter_id": 0,
            "security": "tls",
            "network": "h2",
            "h2_opts": {
                "host": ["your-domain.com"],
                "path": path
            }
        }
    elif network == "grpc":
        return {
            "server": server_ip,
            "server_port": port,
            "uuid": uuid,
            "alter_id": 0,
            "security": "tls",
            "network": "grpc",
            "grpc_opts": {
                "service_name": path
            }
        }

def save_config(config, filename):
    """ذخیره پیکربندی در فایل"""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"✅ پیکربندی در {filename} ذخیره شد")

def main():
    print("🔧 تولیدکننده پیکربندی امن v2ray")
    print("=" * 50)
    
    # دریافت اطلاعات از کاربر
    domain = input("🌐 دامنه سرور را وارد کنید: ").strip()
    server_ip = input("🖥️ IP سرور را وارد کنید: ").strip()
    port = int(input("🔌 پورت سرور را وارد کنید (443): ") or "443")
    
    # تولید پیکربندی‌های مختلف
    configs = {
        "websocket": generate_websocket_config(domain, port),
        "h2": generate_h2_config(domain, port),
        "grpc": generate_grpc_config(domain, port)
    }
    
    # ذخیره پیکربندی‌ها
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for name, config in configs.items():
        filename = f"v2ray_{name}_{timestamp}.json"
        save_config(config, filename)
        
        # استخراج اطلاعات برای کلاینت
        client_uuid = config["inbounds"][0]["settings"]["clients"][0]["id"]
        if name == "websocket":
            client_path = config["inbounds"][0]["streamSettings"]["wsSettings"]["path"]
        elif name == "h2":
            client_path = config["inbounds"][0]["streamSettings"]["httpSettings"]["path"]
        else:  # grpc
            client_path = config["inbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"]
        
        client_config = generate_client_config(server_ip, port, client_uuid, client_path, name)
        client_filename = f"client_{name}_{timestamp}.json"
        save_config(client_config, client_filename)
    
    print("\n🎉 تمام پیکربندی‌ها تولید شدند!")
    print("\n📋 نکات مهم:")
    print("1. فایل‌های سرور را در /etc/v2ray/ قرار دهید")
    print("2. گواهی SSL را برای دامنه خود نصب کنید")
    print("3. از CDN مثل Cloudflare استفاده کنید")
    print("4. مرتباً UUID و مسیرها را تغییر دهید")
    print("5. لاگ‌ها را بررسی کنید")

if __name__ == "__main__":
    main() 