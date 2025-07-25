#!/usr/bin/env python3
"""
اسکریپت تست اتصال v2ray
برای تشخیص مشکلات احتمالی
"""

import requests
import socket
import ssl
import json
import time
import subprocess
import sys
from urllib.parse import urlparse

class V2RayTester:
    def __init__(self, domain, port=443):
        self.domain = domain
        self.port = port
        self.results = {}
    
    def test_dns_resolution(self):
        """تست رزولوشن DNS"""
        print("🔍 تست رزولوشن DNS...")
        try:
            ip = socket.gethostbyname(self.domain)
            self.results['dns'] = {'status': 'success', 'ip': ip}
            print(f"✅ DNS: {self.domain} -> {ip}")
            return True
        except socket.gaierror as e:
            self.results['dns'] = {'status': 'error', 'error': str(e)}
            print(f"❌ DNS Error: {e}")
            return False
    
    def test_port_connectivity(self):
        """تست اتصال پورت"""
        print("🔌 تست اتصال پورت...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((self.domain, self.port))
            sock.close()
            
            if result == 0:
                self.results['port'] = {'status': 'success'}
                print(f"✅ پورت {self.port} باز است")
                return True
            else:
                self.results['port'] = {'status': 'error', 'error': f'Port {self.port} closed'}
                print(f"❌ پورت {self.port} بسته است")
                return False
        except Exception as e:
            self.results['port'] = {'status': 'error', 'error': str(e)}
            print(f"❌ Port Error: {e}")
            return False
    
    def test_ssl_certificate(self):
        """تست گواهی SSL"""
        print("🔒 تست گواهی SSL...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.results['ssl'] = {
                        'status': 'success',
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expiry': cert['notAfter']
                    }
                    print(f"✅ SSL: معتبر تا {cert['notAfter']}")
                    return True
        except Exception as e:
            self.results['ssl'] = {'status': 'error', 'error': str(e)}
            print(f"❌ SSL Error: {e}")
            return False
    
    def test_http_response(self):
        """تست پاسخ HTTP"""
        print("🌐 تست پاسخ HTTP...")
        try:
            url = f"https://{self.domain}"
            response = requests.get(url, timeout=10, verify=True)
            self.results['http'] = {
                'status': 'success',
                'status_code': response.status_code,
                'headers': dict(response.headers)
            }
            print(f"✅ HTTP: {response.status_code}")
            return True
        except Exception as e:
            self.results['http'] = {'status': 'error', 'error': str(e)}
            print(f"❌ HTTP Error: {e}")
            return False
    
    def test_websocket_handshake(self):
        """تست WebSocket handshake"""
        print("🔗 تست WebSocket...")
        try:
            import websocket
            ws = websocket.create_connection(f"wss://{self.domain}/websocket", timeout=10)
            ws.close()
            self.results['websocket'] = {'status': 'success'}
            print("✅ WebSocket: قابل اتصال")
            return True
        except Exception as e:
            self.results['websocket'] = {'status': 'error', 'error': str(e)}
            print(f"❌ WebSocket Error: {e}")
            return False
    
    def test_tls_fingerprint(self):
        """تست فینگرپرینت TLS"""
        print("👆 تست فینگرپرینت TLS...")
        try:
            # تست ALPN
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2', 'http/1.1'])
            
            with socket.create_connection((self.domain, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    alpn = ssock.selected_alpn_protocol()
                    cipher = ssock.cipher()
                    
                    self.results['tls_fingerprint'] = {
                        'status': 'success',
                        'alpn': alpn,
                        'cipher': cipher[0],
                        'version': cipher[1]
                    }
                    print(f"✅ TLS: ALPN={alpn}, Cipher={cipher[0]}")
                    return True
        except Exception as e:
            self.results['tls_fingerprint'] = {'status': 'error', 'error': str(e)}
            print(f"❌ TLS Fingerprint Error: {e}")
            return False
    
    def test_latency(self):
        """تست تاخیر"""
        print("⏱️ تست تاخیر...")
        try:
            start_time = time.time()
            response = requests.get(f"https://{self.domain}", timeout=10)
            latency = (time.time() - start_time) * 1000
            
            self.results['latency'] = {
                'status': 'success',
                'latency_ms': round(latency, 2)
            }
            print(f"✅ تاخیر: {round(latency, 2)}ms")
            return True
        except Exception as e:
            self.results['latency'] = {'status': 'error', 'error': str(e)}
            print(f"❌ Latency Error: {e}")
            return False
    
    def test_geo_location(self):
        """تست موقعیت جغرافیایی"""
        print("🌍 تست موقعیت جغرافیایی...")
        try:
            response = requests.get(f"http://ip-api.com/json/{self.domain}")
            data = response.json()
            
            if data['status'] == 'success':
                self.results['geo'] = {
                    'status': 'success',
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'isp': data.get('isp')
                }
                print(f"✅ موقعیت: {data.get('city')}, {data.get('country')}")
                return True
            else:
                self.results['geo'] = {'status': 'error', 'error': 'Location lookup failed'}
                print("❌ نتوانست موقعیت را پیدا کند")
                return False
        except Exception as e:
            self.results['geo'] = {'status': 'error', 'error': str(e)}
            print(f"❌ Geo Error: {e}")
            return False
    
    def run_all_tests(self):
        """اجرای تمام تست‌ها"""
        print(f"🚀 شروع تست‌ها برای {self.domain}:{self.port}")
        print("=" * 50)
        
        tests = [
            self.test_dns_resolution,
            self.test_port_connectivity,
            self.test_ssl_certificate,
            self.test_http_response,
            self.test_tls_fingerprint,
            self.test_latency,
            self.test_geo_location
        ]
        
        # تست WebSocket فقط اگر پورت 443 باشد
        if self.port == 443:
            tests.append(self.test_websocket_handshake)
        
        for test in tests:
            try:
                test()
                time.sleep(1)  # فاصله بین تست‌ها
            except Exception as e:
                print(f"❌ خطا در تست: {e}")
        
        self.generate_report()
    
    def generate_report(self):
        """تولید گزارش"""
        print("\n" + "=" * 50)
        print("📊 گزارش تست")
        print("=" * 50)
        
        success_count = 0
        total_count = len(self.results)
        
        for test_name, result in self.results.items():
            status = "✅" if result['status'] == 'success' else "❌"
            print(f"{status} {test_name}: {result['status']}")
            if result['status'] == 'success':
                success_count += 1
        
        print(f"\n📈 نتیجه: {success_count}/{total_count} تست موفق")
        
        # توصیه‌ها
        print("\n💡 توصیه‌ها:")
        if self.results.get('dns', {}).get('status') == 'error':
            print("- DNS را بررسی کنید")
        if self.results.get('port', {}).get('status') == 'error':
            print("- فایروال را بررسی کنید")
        if self.results.get('ssl', {}).get('status') == 'error':
            print("- گواهی SSL را بررسی کنید")
        if self.results.get('latency', {}).get('status') == 'success':
            latency = self.results['latency']['latency_ms']
            if latency > 200:
                print("- تاخیر بالا است، CDN استفاده کنید")
        
        # ذخیره گزارش
        with open(f"test_report_{self.domain}_{int(time.time())}.json", 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 گزارش در فایل JSON ذخیره شد")

def main():
    if len(sys.argv) < 2:
        print("استفاده: python3 test-connection.py <domain> [port]")
        print("مثال: python3 test-connection.py example.com 443")
        sys.exit(1)
    
    domain = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    tester = V2RayTester(domain, port)
    tester.run_all_tests()

if __name__ == "__main__":
    main() 