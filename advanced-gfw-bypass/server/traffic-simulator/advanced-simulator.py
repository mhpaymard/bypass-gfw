#!/usr/bin/env python3
"""
Advanced Traffic Simulator
Mimics real website behavior to avoid detection
"""

import asyncio
import json
import random
import time
import hashlib
import base64
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

import aiohttp
from aiohttp import web, ClientSession, ClientTimeout
from aiohttp_cors import setup as cors_setup
import jwt
from cryptography.fernet import Fernet
import redis.asyncio as redis

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class User:
    """User data structure"""
    id: str
    username: str
    email: str
    created_at: datetime
    last_login: datetime
    session_token: str
    bandwidth_used: int
    is_active: bool

@dataclass
class TrafficLog:
    """Traffic log entry"""
    user_id: str
    timestamp: datetime
    bytes_sent: int
    bytes_received: int
    endpoint: str
    user_agent: str
    ip_address: str

class AdvancedTrafficSimulator:
    """Advanced traffic simulator with realistic website behavior"""
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.traffic_logs: List[TrafficLog] = []
        self.sessions: Dict[str, Dict] = {}
        self.rate_limits: Dict[str, List[float]] = {}
        
        # Realistic content types and responses
        self.content_types = {
            "html": "text/html; charset=utf-8",
            "json": "application/json; charset=utf-8",
            "js": "application/javascript; charset=utf-8",
            "css": "text/css; charset=utf-8",
            "png": "image/png",
            "jpg": "image/jpeg",
            "gif": "image/gif",
            "ico": "image/x-icon",
            "svg": "image/svg+xml",
            "woff": "font/woff",
            "woff2": "font/woff2",
            "ttf": "font/ttf",
            "eot": "application/vnd.ms-fontobject"
        }
        
        # Realistic API endpoints
        self.api_endpoints = [
            "/api/v1/users/login",
            "/api/v1/users/register",
            "/api/v1/users/profile",
            "/api/v1/users/settings",
            "/api/v1/files/upload",
            "/api/v1/files/download",
            "/api/v1/chat/messages",
            "/api/v1/chat/rooms",
            "/api/v1/notifications",
            "/api/v1/analytics/track",
            "/api/v1/search",
            "/api/v1/stream/live",
            "/api/v1/payments/process",
            "/api/v1/auth/refresh",
            "/api/v1/backup/restore"
        ]
        
        # Static file paths
        self.static_files = [
            "/static/js/main.js",
            "/static/css/style.css",
            "/static/images/logo.png",
            "/static/images/avatar.jpg",
            "/static/fonts/roboto.woff2",
            "/static/js/analytics.js",
            "/static/css/components.css",
            "/static/images/background.jpg",
            "/static/js/utils.js",
            "/static/css/responsive.css"
        ]
        
        # Initialize encryption
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # JWT secret
        self.jwt_secret = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
        
    async def initialize(self):
        """Initialize the simulator"""
        # Create sample users
        await self.create_sample_users()
        
        # Initialize Redis for session storage
        self.redis = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        
        logger.info("Advanced Traffic Simulator initialized")
    
    async def create_sample_users(self):
        """Create sample users for realistic traffic"""
        sample_users = [
            ("john_doe", "john@example.com"),
            ("jane_smith", "jane@example.com"),
            ("admin", "admin@example.com"),
            ("guest", "guest@example.com"),
            ("test_user", "test@example.com")
        ]
        
        for username, email in sample_users:
            user_id = str(uuid.uuid4())
            user = User(
                id=user_id,
                username=username,
                email=email,
                created_at=datetime.now() - timedelta(days=random.randint(1, 365)),
                last_login=datetime.now() - timedelta(hours=random.randint(1, 24)),
                session_token=self.generate_session_token(),
                bandwidth_used=random.randint(1024, 1024*1024*100),  # 1KB to 100MB
                is_active=True
            )
            self.users[user_id] = user
    
    def generate_session_token(self) -> str:
        """Generate a secure session token"""
        return base64.urlsafe_b64encode(os.urandom(32)).decode()
    
    def check_rate_limit(self, ip: str, endpoint: str) -> bool:
        """Check rate limiting"""
        key = f"{ip}:{endpoint}"
        now = time.time()
        
        if key not in self.rate_limits:
            self.rate_limits[key] = []
        
        # Remove old entries (older than 1 minute)
        self.rate_limits[key] = [t for t in self.rate_limits[key] if now - t < 60]
        
        # Check if too many requests
        if len(self.rate_limits[key]) >= 100:  # 100 requests per minute
            return False
        
        self.rate_limits[key].append(now)
        return True
    
    async def log_traffic(self, user_id: str, bytes_sent: int, bytes_received: int, 
                         endpoint: str, user_agent: str, ip_address: str):
        """Log traffic for monitoring"""
        log = TrafficLog(
            user_id=user_id,
            timestamp=datetime.now(),
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            endpoint=endpoint,
            user_agent=user_agent,
            ip_address=ip_address
        )
        self.traffic_logs.append(log)
        
        # Update user bandwidth
        if user_id in self.users:
            self.users[user_id].bandwidth_used += bytes_sent + bytes_received
    
    def generate_realistic_response(self, endpoint: str) -> Dict[str, Any]:
        """Generate realistic API responses"""
        if "login" in endpoint:
            return {
                "success": True,
                "token": jwt.encode(
                    {"user_id": str(uuid.uuid4()), "exp": datetime.utcnow() + timedelta(hours=24)},
                    self.jwt_secret,
                    algorithm="HS256"
                ),
                "user": {
                    "id": str(uuid.uuid4()),
                    "username": random.choice(["john_doe", "jane_smith", "admin"]),
                    "email": f"{random.choice(['john', 'jane', 'admin'])}@example.com",
                    "avatar": f"https://api.example.com/avatars/{random.randint(1, 100)}.jpg",
                    "preferences": {
                        "theme": random.choice(["light", "dark", "auto"]),
                        "language": random.choice(["en", "es", "fr", "de"]),
                        "notifications": random.choice([True, False])
                    }
                },
                "expires_in": 86400
            }
        
        elif "files" in endpoint:
            return {
                "success": True,
                "files": [
                    {
                        "id": str(uuid.uuid4()),
                        "name": f"document_{random.randint(1, 100)}.pdf",
                        "size": random.randint(1024, 1024*1024*10),
                        "type": "application/pdf",
                        "uploaded_at": (datetime.now() - timedelta(hours=random.randint(1, 168))).isoformat(),
                        "url": f"https://cdn.example.com/files/{uuid.uuid4()}"
                    }
                    for _ in range(random.randint(1, 5))
                ],
                "total_count": random.randint(10, 100),
                "page": random.randint(1, 10),
                "per_page": 20
            }
        
        elif "chat" in endpoint:
            return {
                "success": True,
                "messages": [
                    {
                        "id": str(uuid.uuid4()),
                        "user_id": str(uuid.uuid4()),
                        "username": random.choice(["john_doe", "jane_smith", "admin"]),
                        "content": random.choice([
                            "Hello! How are you?",
                            "Can you help me with this?",
                            "Thanks for the information!",
                            "I'll check it out later.",
                            "That sounds great!"
                        ]),
                        "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
                        "type": "text"
                    }
                    for _ in range(random.randint(1, 10))
                ],
                "room_id": str(uuid.uuid4()),
                "participants": random.randint(2, 10)
            }
        
        elif "analytics" in endpoint:
            return {
                "success": True,
                "data": {
                    "page_views": random.randint(1000, 10000),
                    "unique_visitors": random.randint(100, 1000),
                    "bounce_rate": random.uniform(0.1, 0.8),
                    "avg_session_duration": random.randint(60, 1800),
                    "top_pages": [
                        {"page": "/home", "views": random.randint(100, 1000)},
                        {"page": "/products", "views": random.randint(50, 500)},
                        {"page": "/about", "views": random.randint(20, 200)}
                    ]
                },
                "period": "last_24_hours"
            }
        
        else:
            return {
                "success": True,
                "message": "Operation completed successfully",
                "timestamp": datetime.now().isoformat(),
                "request_id": str(uuid.uuid4())
            }
    
    def generate_static_content(self, file_path: str) -> bytes:
        """Generate realistic static content"""
        if file_path.endswith('.js'):
            return f"""
// {file_path}
(function() {{
    'use strict';
    
    const app = {{
        version: '{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 9)}',
        config: {{
            apiUrl: 'https://api.example.com',
            debug: {str(random.choice([True, False])).lower()},
            features: {{
                analytics: true,
                notifications: true,
                realtime: {str(random.choice([True, False])).lower()}
            }}
        }},
        
        init: function() {{
            console.log('App initialized');
            this.setupEventListeners();
            this.loadAnalytics();
        }},
        
        setupEventListeners: function() {{
            document.addEventListener('DOMContentLoaded', () => {{
                console.log('DOM ready');
            }});
        }},
        
        loadAnalytics: function() {{
            // Analytics code here
            console.log('Analytics loaded');
        }}
    }};
    
    window.app = app;
    app.init();
}})();
""".encode('utf-8')
        
        elif file_path.endswith('.css'):
            return f"""
/* {file_path} */
:root {{
    --primary-color: #{random.randint(0, 0xFFFFFF):06x};
    --secondary-color: #{random.randint(0, 0xFFFFFF):06x};
    --background-color: #{random.randint(0, 0xFFFFFF):06x};
    --text-color: #{random.randint(0, 0xFFFFFF):06x};
}}

body {{
    font-family: 'Roboto', sans-serif;
    margin: 0;
    padding: 0;
    background-color: var(--background-color);
    color: var(--text-color);
}}

.container {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}}

.header {{
    background-color: var(--primary-color);
    padding: 1rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}}

.nav {{
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.btn {{
    background-color: var(--secondary-color);
    color: white;
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    transition: opacity 0.3s ease;
}}

.btn:hover {{
    opacity: 0.8;
}}

@media (max-width: 768px) {{
    .container {{
        padding: 10px;
    }}
}}
""".encode('utf-8')
        
        else:
            # Return a small placeholder image or icon
            return b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\tpHYs\x00\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\x0cIDATx\x9cc```\x00\x00\x00\x04\x00\x01\xf5\xf7\xd0\xd4\x00\x00\x00\x00IEND\xaeB`\x82'
    
    async def handle_api_request(self, request: web.Request) -> web.Response:
        """Handle API requests with realistic responses"""
        endpoint = request.path
        user_agent = request.headers.get('User-Agent', 'Unknown')
        ip_address = request.remote
        
        # Check rate limiting
        if not self.check_rate_limit(ip_address, endpoint):
            return web.json_response(
                {"error": "Rate limit exceeded", "retry_after": 60},
                status=429
            )
        
        # Simulate processing time
        await asyncio.sleep(random.uniform(0.1, 0.5))
        
        # Generate realistic response
        response_data = self.generate_realistic_response(endpoint)
        
        # Log traffic
        await self.log_traffic(
            user_id=str(uuid.uuid4()),
            bytes_sent=len(json.dumps(response_data).encode()),
            bytes_received=len(str(request.headers).encode()),
            endpoint=endpoint,
            user_agent=user_agent,
            ip_address=ip_address
        )
        
        return web.json_response(
            response_data,
            headers={
                'Content-Type': 'application/json; charset=utf-8',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0',
                'X-Request-ID': str(uuid.uuid4()),
                'X-Response-Time': f"{random.randint(50, 200)}ms"
            }
        )
    
    async def handle_static_file(self, request: web.Request) -> web.Response:
        """Handle static file requests"""
        file_path = request.path
        user_agent = request.headers.get('User-Agent', 'Unknown')
        ip_address = request.remote
        
        # Check rate limiting
        if not self.check_rate_limit(ip_address, file_path):
            return web.Response(status=429)
        
        # Simulate file loading time
        await asyncio.sleep(random.uniform(0.05, 0.2))
        
        # Generate content
        content = self.generate_static_content(file_path)
        
        # Determine content type
        content_type = self.content_types.get(file_path.split('.')[-1], 'application/octet-stream')
        
        # Log traffic
        await self.log_traffic(
            user_id=str(uuid.uuid4()),
            bytes_sent=len(content),
            bytes_received=len(str(request.headers).encode()),
            endpoint=file_path,
            user_agent=user_agent,
            ip_address=ip_address
        )
        
        return web.Response(
            body=content,
            headers={
                'Content-Type': content_type,
                'Cache-Control': 'public, max-age=3600',
                'ETag': f'"{hashlib.md5(content).hexdigest()}"',
                'Last-Modified': (datetime.now() - timedelta(hours=random.randint(1, 24))).strftime('%a, %d %b %Y %H:%M:%S GMT')
            }
        )
    
    async def handle_root(self, request: web.Request) -> web.Response:
        """Handle root requests with realistic HTML"""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Example Website - Advanced Traffic Simulator</title>
    <link rel="stylesheet" href="/static/css/style.css">
    <link rel="icon" href="/static/images/favicon.ico">
</head>
<body>
    <header class="header">
        <nav class="nav">
            <div class="logo">
                <h1>Example Website</h1>
            </div>
            <div class="nav-links">
                <a href="/" class="nav-link">Home</a>
                <a href="/about" class="nav-link">About</a>
                <a href="/contact" class="nav-link">Contact</a>
                <a href="/login" class="btn">Login</a>
            </div>
        </nav>
    </header>
    
    <main class="container">
        <section class="hero">
            <h2>Welcome to Our Platform</h2>
            <p>This is a realistic website that simulates normal traffic patterns.</p>
            <button class="btn" onclick="loadAnalytics()">Get Started</button>
        </section>
        
        <section class="features">
            <div class="feature">
                <h3>Feature 1</h3>
                <p>Description of feature 1</p>
            </div>
            <div class="feature">
                <h3>Feature 2</h3>
                <p>Description of feature 2</p>
            </div>
            <div class="feature">
                <h3>Feature 3</h3>
                <p>Description of feature 3</p>
            </div>
        </section>
    </main>
    
    <footer>
        <p>&copy; 2024 Example Website. All rights reserved.</p>
    </footer>
    
    <script src="/static/js/main.js"></script>
    <script>
        function loadAnalytics() {{
            fetch('/api/v1/analytics/track', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{
                    event: 'button_click',
                    page: '/',
                    timestamp: new Date().toISOString()
                }})
            }});
        }}
    </script>
</body>
</html>
"""
        
        return web.Response(
            text=html_content,
            headers={
                'Content-Type': 'text/html; charset=utf-8',
                'Cache-Control': 'no-cache',
                'X-Request-ID': str(uuid.uuid4())
            }
        )
    
    async def create_app(self) -> web.Application:
        """Create the web application"""
        app = web.Application()
        
        # Setup CORS
        cors = cors_setup(app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        
        # Add routes
        app.router.add_get('/', self.handle_root)
        
        # API routes
        for endpoint in self.api_endpoints:
            app.router.add_post(endpoint, self.handle_api_request)
            app.router.add_get(endpoint, self.handle_api_request)
        
        # Static file routes
        for file_path in self.static_files:
            app.router.add_get(file_path, self.handle_static_file)
        
        # Add CORS to all routes
        for route in list(app.router.routes()):
            cors.add(route)
        
        return app

async def main():
    """Main function"""
    simulator = AdvancedTrafficSimulator()
    await simulator.initialize()
    
    app = await simulator.create_app()
    
    # Start the server
    runner = web.AppRunner(app)
    await runner.setup()
    
    site = web.TCPSite(runner, '0.0.0.0', 8080)
    await site.start()
    
    logger.info("Advanced Traffic Simulator running on http://0.0.0.0:8080")
    
    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main()) 