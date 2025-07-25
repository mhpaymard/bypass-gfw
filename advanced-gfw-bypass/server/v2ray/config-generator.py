#!/usr/bin/env python3
"""
Advanced V2Ray Configuration Generator
Combines multiple evasion techniques for maximum undetectability
"""

import json
import uuid
import random
import hashlib
import base64
import time
import os
import sys
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path

@dataclass
class ServerConfig:
    """Server configuration parameters"""
    host: str
    port: int
    protocol: str
    uuid: str
    path: str
    domain: str
    sni: str
    alpn: List[str]
    fingerprint: str
    security: str
    flow: str
    network: str

class AdvancedV2RayGenerator:
    """Advanced V2Ray configuration generator with multiple evasion layers"""
    
    def __init__(self):
        self.popular_domains = [
            "www.google.com", "github.com", "cloudflare.com", "amazon.com",
            "microsoft.com", "apple.com", "netflix.com", "facebook.com",
            "twitter.com", "instagram.com", "linkedin.com", "stackoverflow.com",
            "reddit.com", "wikipedia.org", "youtube.com", "spotify.com"
        ]
        
        self.browser_fingerprints = [
            "chrome", "firefox", "safari", "edge", "opera", "random"
        ]
        
        self.alpn_options = [
            ["h2", "http/1.1"],
            ["h3", "h2", "http/1.1"],
            ["http/1.1"],
            ["h2"],
            ["h3"]
        ]
        
        self.network_types = ["ws", "http", "grpc", "quic"]
        
    def generate_uuid(self) -> str:
        """Generate a cryptographically secure UUID"""
        return str(uuid.uuid4())
    
    def generate_path(self) -> str:
        """Generate a realistic-looking path"""
        paths = [
            "/api/v1/analytics",
            "/cdn/static/js/main.js",
            "/api/graphql",
            "/_next/static/chunks/main.js",
            "/wp-content/plugins/woocommerce/assets/js/frontend/cart.js",
            "/static/js/bundle.js",
            "/api/rest/v1/users",
            "/api/v2/notifications",
            "/assets/js/app.js",
            "/api/v3/search",
            "/static/css/main.css",
            "/api/health/check",
            "/cdn/analytics/track",
            "/api/v1/metrics",
            "/static/images/logo.png"
        ]
        return random.choice(paths)
    
    def generate_sni(self) -> str:
        """Generate a realistic SNI value"""
        return random.choice(self.popular_domains)
    
    def generate_alpn(self) -> List[str]:
        """Generate ALPN protocol list"""
        return random.choice(self.alpn_options)
    
    def generate_fingerprint(self) -> str:
        """Generate browser fingerprint"""
        return random.choice(self.browser_fingerprints)
    
    def create_websocket_config(self, config: ServerConfig) -> Dict:
        """Create WebSocket configuration with advanced evasion"""
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": config.host,
                    "port": config.port,
                    "users": [{
                        "id": config.uuid,
                        "alterId": 0,
                        "security": config.security,
                        "level": 0
                    }]
                }]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": config.sni,
                    "alpn": config.alpn,
                    "fingerprint": config.fingerprint,
                    "allowInsecure": False,
                    "certificates": [{
                        "certificateFile": f"/etc/ssl/certs/{config.domain}.crt",
                        "keyFile": f"/etc/ssl/private/{config.domain}.key"
                    }]
                },
                "wsSettings": {
                    "path": config.path,
                    "headers": {
                        "Host": config.domain,
                        "User-Agent": self.generate_user_agent(),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                        "Upgrade": "websocket",
                        "Sec-WebSocket-Version": "13"
                    }
                }
            }
        }
    
    def create_http_config(self, config: ServerConfig) -> Dict:
        """Create HTTP/2 configuration with advanced evasion"""
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": config.host,
                    "port": config.port,
                    "users": [{
                        "id": config.uuid,
                        "alterId": 0,
                        "security": config.security,
                        "level": 0
                    }]
                }]
            },
            "streamSettings": {
                "network": "http",
                "security": "tls",
                "tlsSettings": {
                    "serverName": config.sni,
                    "alpn": config.alpn,
                    "fingerprint": config.fingerprint,
                    "allowInsecure": False,
                    "certificates": [{
                        "certificateFile": f"/etc/ssl/certs/{config.domain}.crt",
                        "keyFile": f"/etc/ssl/private/{config.domain}.key"
                    }]
                },
                "httpSettings": {
                    "host": [config.domain],
                    "path": config.path,
                    "method": "GET",
                    "headers": {
                        "User-Agent": self.generate_user_agent(),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Cache-Control": "no-cache",
                        "Pragma": "no-cache"
                    }
                }
            }
        }
    
    def create_grpc_config(self, config: ServerConfig) -> Dict:
        """Create gRPC configuration with advanced evasion"""
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": config.host,
                    "port": config.port,
                    "users": [{
                        "id": config.uuid,
                        "alterId": 0,
                        "security": config.security,
                        "level": 0
                    }]
                }]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "serverName": config.sni,
                    "alpn": config.alpn,
                    "fingerprint": config.fingerprint,
                    "allowInsecure": False,
                    "certificates": [{
                        "certificateFile": f"/etc/ssl/certs/{config.domain}.crt",
                        "keyFile": f"/etc/ssl/private/{config.domain}.key"
                    }]
                },
                "grpcSettings": {
                    "serviceName": config.path.strip('/'),
                    "multiMode": True,
                    "idle_timeout": 60,
                    "health_check_timeout": 20,
                    "permit_without_stream": True,
                    "user_agent": self.generate_user_agent()
                }
            }
        }
    
    def generate_user_agent(self) -> str:
        """Generate realistic User-Agent strings"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
        ]
        return random.choice(user_agents)
    
    def create_server_config(self, config: ServerConfig) -> Dict:
        """Create complete server configuration"""
        return {
            "log": {
                "loglevel": "warning",
                "access": "/var/log/v2ray/access.log",
                "error": "/var/log/v2ray/error.log"
            },
            "inbounds": [{
                "port": config.port,
                "protocol": "vmess",
                "settings": {
                    "clients": [{
                        "id": config.uuid,
                        "alterId": 0,
                        "security": config.security,
                        "level": 0,
                        "email": f"user_{hashlib.md5(config.uuid.encode()).hexdigest()[:8]}@example.com"
                    }],
                    "default": {
                        "level": 0,
                        "alterId": 0
                    },
                    "disableInsecureEncryption": True
                },
                "streamSettings": self._get_stream_settings(config),
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            }],
            "outbounds": [{
                "protocol": "freedom",
                "settings": {},
                "tag": "direct"
            }, {
                "protocol": "blackhole",
                "settings": {},
                "tag": "blocked"
            }],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [{
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "blocked"
                }]
            }
        }
    
    def _get_stream_settings(self, config: ServerConfig) -> Dict:
        """Get stream settings based on network type"""
        base_settings = {
            "network": config.network,
            "security": "tls",
            "tlsSettings": {
                "serverName": config.sni,
                "alpn": config.alpn,
                "fingerprint": config.fingerprint,
                "allowInsecure": False,
                "certificates": [{
                    "certificateFile": f"/etc/ssl/certs/{config.domain}.crt",
                    "keyFile": f"/etc/ssl/private/{config.domain}.key"
                }]
            }
        }
        
        if config.network == "ws":
            base_settings["wsSettings"] = {
                "path": config.path,
                "headers": {
                    "Host": config.domain,
                    "User-Agent": self.generate_user_agent(),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade": "websocket",
                    "Sec-WebSocket-Version": "13"
                }
            }
        elif config.network == "http":
            base_settings["httpSettings"] = {
                "host": [config.domain],
                "path": config.path,
                "method": "GET",
                "headers": {
                    "User-Agent": self.generate_user_agent(),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache"
                }
            }
        elif config.network == "grpc":
            base_settings["grpcSettings"] = {
                "serviceName": config.path.strip('/'),
                "multiMode": True,
                "idle_timeout": 60,
                "health_check_timeout": 20,
                "permit_without_stream": True,
                "user_agent": self.generate_user_agent()
            }
        
        return base_settings
    
    def generate_config(self, host: str, port: int, domain: str, 
                       protocol: str = "ws", security: str = "auto") -> Dict:
        """Generate complete configuration"""
        config = ServerConfig(
            host=host,
            port=port,
            protocol=protocol,
            uuid=self.generate_uuid(),
            path=self.generate_path(),
            domain=domain,
            sni=self.generate_sni(),
            alpn=self.generate_alpn(),
            fingerprint=self.generate_fingerprint(),
            security=security,
            flow="",
            network=protocol
        )
        
        return {
            "server": self.create_server_config(config),
            "client": self.create_client_config(config),
            "metadata": {
                "generated_at": time.time(),
                "version": "2.0.0",
                "config_hash": hashlib.sha256(json.dumps(config.__dict__, sort_keys=True).encode()).hexdigest()
            }
        }
    
    def create_client_config(self, config: ServerConfig) -> Dict:
        """Create client configuration"""
        return {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [{
                "port": 1080,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                }
            }, {
                "port": 1081,
                "protocol": "http",
                "settings": {
                    "timeout": 300
                }
            }],
            "outbounds": [{
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": config.host,
                        "port": config.port,
                        "users": [{
                            "id": config.uuid,
                            "alterId": 0,
                            "security": config.security,
                            "level": 0
                        }]
                    }]
                },
                "streamSettings": self._get_stream_settings(config),
                "tag": "proxy"
            }, {
                "protocol": "freedom",
                "settings": {},
                "tag": "direct"
            }],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [{
                    "type": "field",
                    "domain": ["geosite:cn"],
                    "outboundTag": "direct"
                }, {
                    "type": "field",
                    "ip": ["geoip:private", "geoip:cn"],
                    "outboundTag": "direct"
                }]
            }
        }

def main():
    """Main function to generate configurations"""
    generator = AdvancedV2RayGenerator()
    
    # Example usage
    config = generator.generate_config(
        host="your-server.com",
        port=443,
        domain="your-domain.com",
        protocol="ws",
        security="auto"
    )
    
    # Save configurations
    output_dir = Path("configs")
    output_dir.mkdir(exist_ok=True)
    
    with open(output_dir / "server.json", "w") as f:
        json.dump(config["server"], f, indent=2)
    
    with open(output_dir / "client.json", "w") as f:
        json.dump(config["client"], f, indent=2)
    
    with open(output_dir / "metadata.json", "w") as f:
        json.dump(config["metadata"], f, indent=2)
    
    print("✅ Configuration generated successfully!")
    print(f"📁 Configs saved to: {output_dir}")
    print(f"🔑 UUID: {config['client']['outbounds'][0]['settings']['vnext'][0]['users'][0]['id']}")
    print(f"🌐 Path: {config['client']['outbounds'][0]['streamSettings'].get('wsSettings', {}).get('path', 'N/A')}")

if __name__ == "__main__":
    main() 