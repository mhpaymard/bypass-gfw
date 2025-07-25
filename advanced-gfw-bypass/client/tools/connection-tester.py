#!/usr/bin/env python3
"""
Advanced Connection Tester
Tests connection quality and provides detailed diagnostics
"""

import asyncio
import json
import time
import socket
import ssl
import requests
import subprocess
import platform
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import argparse

@dataclass
class ConnectionTest:
    """Connection test result"""
    timestamp: datetime
    server: str
    port: int
    protocol: str
    latency: float
    bandwidth: float
    success: bool
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

@dataclass
class NetworkInfo:
    """Network information"""
    local_ip: str
    public_ip: str
    isp: str
    location: str
    dns_servers: List[str]
    routing_info: Dict[str, Any]

class AdvancedConnectionTester:
    """Advanced connection testing tool"""
    
    def __init__(self):
        self.test_results: List[ConnectionTest] = []
        self.network_info: Optional[NetworkInfo] = None
        
    async def get_network_info(self) -> NetworkInfo:
        """Get network information"""
        try:
            # Get local IP
            local_ip = self.get_local_ip()
            
            # Get public IP and ISP info
            public_ip, isp, location = await self.get_public_info()
            
            # Get DNS servers
            dns_servers = self.get_dns_servers()
            
            # Get routing information
            routing_info = await self.get_routing_info()
            
            self.network_info = NetworkInfo(
                local_ip=local_ip,
                public_ip=public_ip,
                isp=isp,
                location=location,
                dns_servers=dns_servers,
                routing_info=routing_info
            )
            
            return self.network_info
            
        except Exception as e:
            print(f"Error getting network info: {e}")
            return None
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    async def get_public_info(self) -> tuple:
        """Get public IP, ISP, and location"""
        try:
            # Try multiple services for redundancy
            services = [
                "https://ipapi.co/json/",
                "https://ipinfo.io/json",
                "https://api.ipify.org?format=json"
            ]
            
            for service in services:
                try:
                    response = requests.get(service, timeout=10)
                    data = response.json()
                    
                    if "ip" in data:
                        public_ip = data["ip"]
                        isp = data.get("org", data.get("isp", "Unknown"))
                        location = f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
                        return public_ip, isp, location
                        
                except Exception:
                    continue
            
            return "Unknown", "Unknown", "Unknown"
            
        except Exception as e:
            print(f"Error getting public info: {e}")
            return "Unknown", "Unknown", "Unknown"
    
    def get_dns_servers(self) -> List[str]:
        """Get DNS servers"""
        try:
            if platform.system() == "Windows":
                # Windows
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                dns_servers = []
                for line in lines:
                    if "DNS Servers" in line:
                        dns = line.split(":")[-1].strip()
                        if dns and dns != "0.0.0.0":
                            dns_servers.append(dns)
                return dns_servers
            else:
                # Linux/macOS
                with open("/etc/resolv.conf", "r") as f:
                    lines = f.readlines()
                    return [line.split()[1] for line in lines if line.startswith("nameserver")]
        except Exception:
            return ["8.8.8.8", "1.1.1.1"]
    
    async def get_routing_info(self) -> Dict[str, Any]:
        """Get routing information"""
        try:
            # Test route to common destinations
            destinations = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
            routes = {}
            
            for dest in destinations:
                try:
                    if platform.system() == "Windows":
                        result = subprocess.run(["tracert", "-h", "15", dest], 
                                              capture_output=True, text=True, timeout=30)
                    else:
                        result = subprocess.run(["traceroute", "-m", "15", dest], 
                                              capture_output=True, text=True, timeout=30)
                    
                    routes[dest] = {
                        "output": result.stdout,
                        "success": result.returncode == 0
                    }
                except Exception:
                    routes[dest] = {"success": False, "error": "Timeout"}
            
            return routes
            
        except Exception as e:
            return {"error": str(e)}
    
    async def test_tcp_connection(self, server: str, port: int, timeout: float = 10.0) -> ConnectionTest:
        """Test TCP connection"""
        start_time = time.time()
        success = False
        error = None
        details = {}
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect
            sock.connect((server, port))
            success = True
            
            # Test SSL if port is 443
            if port == 443:
                try:
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=server) as ssock:
                        cert = ssock.getpeercert()
                        details["ssl"] = {
                            "version": ssock.version(),
                            "cipher": ssock.cipher(),
                            "cert_subject": dict(x[0] for x in cert['subject']),
                            "cert_issuer": dict(x[0] for x in cert['issuer'])
                        }
                except Exception as e:
                    details["ssl_error"] = str(e)
            
            sock.close()
            
        except socket.timeout:
            error = "Connection timeout"
        except ConnectionRefusedError:
            error = "Connection refused"
        except Exception as e:
            error = str(e)
        
        latency = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        test = ConnectionTest(
            timestamp=datetime.now(),
            server=server,
            port=port,
            protocol="TCP",
            latency=latency,
            bandwidth=0,  # TCP test doesn't measure bandwidth
            success=success,
            error=error,
            details=details
        )
        
        self.test_results.append(test)
        return test
    
    async def test_http_connection(self, url: str, timeout: float = 10.0) -> ConnectionTest:
        """Test HTTP connection"""
        start_time = time.time()
        success = False
        error = None
        details = {}
        
        try:
            response = requests.get(url, timeout=timeout, stream=True)
            success = response.status_code == 200
            
            # Calculate bandwidth (rough estimate)
            content_length = response.headers.get('content-length')
            if content_length:
                transfer_time = time.time() - start_time
                bandwidth = int(content_length) / transfer_time / 1024  # KB/s
            else:
                bandwidth = 0
            
            details["http"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_length": content_length
            }
            
            response.close()
            
        except requests.exceptions.Timeout:
            error = "HTTP request timeout"
            bandwidth = 0
        except requests.exceptions.ConnectionError:
            error = "HTTP connection error"
            bandwidth = 0
        except Exception as e:
            error = str(e)
            bandwidth = 0
        
        latency = (time.time() - start_time) * 1000
        
        test = ConnectionTest(
            timestamp=datetime.now(),
            server=url,
            port=80 if url.startswith("http://") else 443,
            protocol="HTTP",
            latency=latency,
            bandwidth=bandwidth,
            success=success,
            error=error,
            details=details
        )
        
        self.test_results.append(test)
        return test
    
    async def test_websocket_connection(self, url: str, timeout: float = 10.0) -> ConnectionTest:
        """Test WebSocket connection"""
        start_time = time.time()
        success = False
        error = None
        details = {}
        
        try:
            import websockets
            
            async with websockets.connect(url, timeout=timeout) as websocket:
                # Send a test message
                await websocket.send("ping")
                response = await websocket.recv()
                
                success = response == "pong"
                details["websocket"] = {
                    "protocol": websocket.protocol,
                    "response": response
                }
                
        except ImportError:
            error = "websockets library not installed"
        except Exception as e:
            error = str(e)
        
        latency = (time.time() - start_time) * 1000
        
        test = ConnectionTest(
            timestamp=datetime.now(),
            server=url,
            port=80 if url.startswith("ws://") else 443,
            protocol="WebSocket",
            latency=latency,
            bandwidth=0,
            success=success,
            error=error,
            details=details
        )
        
        self.test_results.append(test)
        return test
    
    async def test_v2ray_connection(self, config_path: str) -> ConnectionTest:
        """Test V2Ray connection using configuration file"""
        start_time = time.time()
        success = False
        error = None
        details = {}
        
        try:
            # Load V2Ray configuration
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Extract connection details
            outbound = config['outbounds'][0]
            settings = outbound['settings']['vnext'][0]
            server = settings['address']
            port = settings['port']
            
            # Test basic connectivity first
            tcp_test = await self.test_tcp_connection(server, port)
            
            if tcp_test.success:
                # Test HTTP/HTTPS if it's an HTTP outbound
                if outbound['streamSettings']['network'] == 'http':
                    protocol = "https" if outbound['streamSettings']['security'] == 'tls' else "http"
                    url = f"{protocol}://{server}:{port}"
                    http_test = await self.test_http_connection(url)
                    success = http_test.success
                    details["http_test"] = asdict(http_test)
                
                # Test WebSocket if it's a WebSocket outbound
                elif outbound['streamSettings']['network'] == 'ws':
                    protocol = "wss" if outbound['streamSettings']['security'] == 'tls' else "ws"
                    ws_path = outbound['streamSettings']['wsSettings']['path']
                    url = f"{protocol}://{server}:{port}{ws_path}"
                    ws_test = await self.test_websocket_connection(url)
                    success = ws_test.success
                    details["websocket_test"] = asdict(ws_test)
                
                else:
                    success = True  # Assume success for other protocols
            else:
                error = f"TCP connection failed: {tcp_test.error}"
            
            details["v2ray_config"] = {
                "protocol": outbound['protocol'],
                "network": outbound['streamSettings']['network'],
                "security": outbound['streamSettings']['security']
            }
            
        except FileNotFoundError:
            error = f"Configuration file not found: {config_path}"
        except json.JSONDecodeError:
            error = f"Invalid JSON in configuration file: {config_path}"
        except Exception as e:
            error = str(e)
        
        latency = (time.time() - start_time) * 1000
        
        test = ConnectionTest(
            timestamp=datetime.now(),
            server=config_path,
            port=0,
            protocol="V2Ray",
            latency=latency,
            bandwidth=0,
            success=success,
            error=error,
            details=details
        )
        
        self.test_results.append(test)
        return test
    
    async def run_comprehensive_test(self, servers: List[str] = None) -> Dict[str, Any]:
        """Run comprehensive connection tests"""
        if servers is None:
            servers = [
                "8.8.8.8",  # Google DNS
                "1.1.1.1",  # Cloudflare DNS
                "208.67.222.222",  # OpenDNS
                "google.com",
                "github.com",
                "cloudflare.com"
            ]
        
        print("🔍 Running comprehensive connection tests...")
        
        # Get network information
        network_info = await self.get_network_info()
        
        # Test basic connectivity
        print("📡 Testing basic connectivity...")
        for server in servers:
            print(f"  Testing {server}...")
            await self.test_tcp_connection(server, 80)
            await self.test_tcp_connection(server, 443)
        
        # Test HTTP connections
        print("🌐 Testing HTTP connections...")
        http_urls = [
            "http://httpbin.org/get",
            "https://httpbin.org/get",
            "https://www.google.com",
            "https://www.github.com"
        ]
        
        for url in http_urls:
            print(f"  Testing {url}...")
            await self.test_http_connection(url)
        
        # Generate report
        return self.generate_report(network_info)
    
    def generate_report(self, network_info: NetworkInfo) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        successful_tests = [t for t in self.test_results if t.success]
        failed_tests = [t for t in self.test_results if not t.success]
        
        if successful_tests:
            avg_latency = sum(t.latency for t in successful_tests) / len(successful_tests)
            avg_bandwidth = sum(t.bandwidth for t in successful_tests if t.bandwidth > 0) / max(1, len([t for t in successful_tests if t.bandwidth > 0]))
        else:
            avg_latency = 0
            avg_bandwidth = 0
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "network_info": asdict(network_info) if network_info else None,
            "summary": {
                "total_tests": len(self.test_results),
                "successful_tests": len(successful_tests),
                "failed_tests": len(failed_tests),
                "success_rate": len(successful_tests) / len(self.test_results) if self.test_results else 0,
                "average_latency_ms": avg_latency,
                "average_bandwidth_kbps": avg_bandwidth
            },
            "tests_by_protocol": {},
            "failed_tests": [asdict(t) for t in failed_tests],
            "recommendations": self.generate_recommendations()
        }
        
        # Group tests by protocol
        for test in self.test_results:
            protocol = test.protocol
            if protocol not in report["tests_by_protocol"]:
                report["tests_by_protocol"][protocol] = []
            report["tests_by_protocol"][protocol].append(asdict(test))
        
        return report
    
    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        successful_tests = [t for t in self.test_results if t.success]
        failed_tests = [t for t in self.test_results if not t.success]
        
        if not successful_tests:
            recommendations.append("❌ No successful connections detected. Check your internet connection.")
            return recommendations
        
        # Latency recommendations
        avg_latency = sum(t.latency for t in successful_tests) / len(successful_tests)
        if avg_latency > 200:
            recommendations.append("⚠️  High latency detected. Consider using a closer server.")
        elif avg_latency < 50:
            recommendations.append("✅ Excellent latency detected.")
        
        # Bandwidth recommendations
        bandwidth_tests = [t for t in successful_tests if t.bandwidth > 0]
        if bandwidth_tests:
            avg_bandwidth = sum(t.bandwidth for t in bandwidth_tests) / len(bandwidth_tests)
            if avg_bandwidth < 1000:  # Less than 1 MB/s
                recommendations.append("⚠️  Low bandwidth detected. Check your internet speed.")
            elif avg_bandwidth > 10000:  # More than 10 MB/s
                recommendations.append("✅ Excellent bandwidth detected.")
        
        # Protocol recommendations
        protocols = set(t.protocol for t in successful_tests)
        if "HTTPS" in protocols:
            recommendations.append("✅ HTTPS connections working properly.")
        if "WebSocket" in protocols:
            recommendations.append("✅ WebSocket connections working properly.")
        
        # Failed tests analysis
        if failed_tests:
            tcp_failures = [t for t in failed_tests if t.protocol == "TCP"]
            if tcp_failures:
                recommendations.append("⚠️  Some TCP connections failed. Check firewall settings.")
            
            http_failures = [t for t in failed_tests if t.protocol == "HTTP"]
            if http_failures:
                recommendations.append("⚠️  Some HTTP connections failed. Check proxy settings.")
        
        return recommendations
    
    def print_report(self, report: Dict[str, Any]):
        """Print formatted report"""
        print("\n" + "="*60)
        print("🔍 ADVANCED CONNECTION TEST REPORT")
        print("="*60)
        
        # Network Information
        if report["network_info"]:
            ni = report["network_info"]
            print(f"\n📡 NETWORK INFORMATION:")
            print(f"  Local IP: {ni['local_ip']}")
            print(f"  Public IP: {ni['public_ip']}")
            print(f"  ISP: {ni['isp']}")
            print(f"  Location: {ni['location']}")
            print(f"  DNS Servers: {', '.join(ni['dns_servers'])}")
        
        # Summary
        summary = report["summary"]
        print(f"\n📊 SUMMARY:")
        print(f"  Total Tests: {summary['total_tests']}")
        print(f"  Successful: {summary['successful_tests']}")
        print(f"  Failed: {summary['failed_tests']}")
        print(f"  Success Rate: {summary['success_rate']:.1%}")
        print(f"  Average Latency: {summary['average_latency_ms']:.1f}ms")
        print(f"  Average Bandwidth: {summary['average_bandwidth_kbps']:.1f} KB/s")
        
        # Tests by Protocol
        print(f"\n🔧 TESTS BY PROTOCOL:")
        for protocol, tests in report["tests_by_protocol"].items():
            successful = len([t for t in tests if t['success']])
            total = len(tests)
            print(f"  {protocol}: {successful}/{total} successful")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in report["recommendations"]:
            print(f"  {rec}")
        
        # Failed Tests
        if report["failed_tests"]:
            print(f"\n❌ FAILED TESTS:")
            for test in report["failed_tests"][:5]:  # Show first 5
                print(f"  {test['server']}:{test['port']} ({test['protocol']}) - {test['error']}")
            if len(report["failed_tests"]) > 5:
                print(f"  ... and {len(report["failed_tests"]) - 5} more")
        
        print("\n" + "="*60)

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Advanced Connection Tester")
    parser.add_argument("--server", help="Test specific server")
    parser.add_argument("--port", type=int, help="Test specific port")
    parser.add_argument("--config", help="Test V2Ray configuration file")
    parser.add_argument("--comprehensive", action="store_true", help="Run comprehensive tests")
    parser.add_argument("--output", help="Save report to file")
    
    args = parser.parse_args()
    
    tester = AdvancedConnectionTester()
    
    if args.config:
        # Test V2Ray configuration
        print(f"🔧 Testing V2Ray configuration: {args.config}")
        result = await tester.test_v2ray_connection(args.config)
        print(f"Result: {'✅ Success' if result.success else '❌ Failed'}")
        if result.error:
            print(f"Error: {result.error}")
    
    elif args.server and args.port:
        # Test specific server and port
        print(f"🔧 Testing {args.server}:{args.port}")
        result = await tester.test_tcp_connection(args.server, args.port)
        print(f"Result: {'✅ Success' if result.success else '❌ Failed'}")
        print(f"Latency: {result.latency:.1f}ms")
        if result.error:
            print(f"Error: {result.error}")
    
    elif args.comprehensive:
        # Run comprehensive tests
        report = await tester.run_comprehensive_test()
        tester.print_report(report)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📄 Report saved to: {args.output}")
    
    else:
        # Default comprehensive test
        print("🔍 Running default comprehensive tests...")
        report = await tester.run_comprehensive_test()
        tester.print_report(report)

if __name__ == "__main__":
    asyncio.run(main()) 