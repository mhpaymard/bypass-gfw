#!/usr/bin/env python3
"""
شبیه‌ساز ترافیک واقعی برای v2ray
با قابلیت محاسبه حجم کاربران و شبیه‌سازی کامل وب‌سایت
"""

import json
import uuid
import random
import time
import os
import sqlite3
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
import threading
import requests
from werkzeug.security import generate_password_hash, check_password_hash

class RealisticTrafficSimulator:
    def __init__(self, domain, port=443):
        self.domain = domain
        self.port = port
        self.app = Flask(__name__)
        self.app.secret_key = os.urandom(24)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # تنظیمات دیتابیس
        self.db_path = "/var/lib/v2ray/users.db"
        self.init_database()
        
        # تنظیمات v2ray
        self.v2ray_config_path = "/etc/v2ray/config.json"
        self.v2ray_uuid = self.generate_stable_uuid()
        self.v2ray_path = "/api/v1/ws"  # ثابت
        
        # تنظیمات CDN
        self.cdn_enabled = True
        self.cdn_fallback = True
        
        self.setup_routes()
        self.setup_v2ray_config()
    
    def init_database(self):
        """راه‌اندازی دیتابیس کاربران"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # جدول کاربران
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                uuid TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                role TEXT DEFAULT 'user'
            )
        ''')
        
        # جدول ترافیک
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                bytes_uploaded BIGINT DEFAULT 0,
                bytes_downloaded BIGINT DEFAULT 0,
                session_duration INTEGER DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # جدول جلسات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_id TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # جدول آمار
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE UNIQUE,
                total_users INTEGER DEFAULT 0,
                active_users INTEGER DEFAULT 0,
                total_traffic BIGINT DEFAULT 0,
                total_sessions INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def generate_stable_uuid(self):
        """تولید UUID ثابت بر اساس دامنه"""
        seed = hashlib.md5(self.domain.encode()).hexdigest()
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))
    
    def setup_v2ray_config(self):
        """تنظیم پیکربندی v2ray ثابت"""
        config = {
            "inbounds": [{
                "port": self.port,
                "protocol": "vmess",
                "settings": {
                    "clients": [{
                        "id": self.v2ray_uuid,
                        "alterId": 0
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {
                        "path": self.v2ray_path,
                        "headers": {
                            "Host": self.domain
                        }
                    },
                    "tlsSettings": {
                        "serverName": self.domain,
                        "fingerprint": "chrome",
                        "alpn": ["h2", "http/1.1"],
                        "certificates": [{
                            "certificateFile": f"/etc/v2ray/certs/{self.domain}.pem",
                            "keyFile": f"/etc/v2ray/certs/{self.domain}.key"
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
        
        # ذخیره پیکربندی
        with open(self.v2ray_config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        # راه‌اندازی مجدد v2ray
        os.system("systemctl restart v2ray")
    
    def setup_routes(self):
        """تنظیم مسیرهای وب‌سایت"""
        
        @self.app.route('/')
        def index():
            """صفحه اصلی"""
            return render_template('index.html', domain=self.domain)
        
        @self.app.route('/api/auth/login', methods=['POST'])
        def login():
            """ورود کاربر"""
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            if self.authenticate_user(username, password):
                session_id = self.create_session(username)
                return jsonify({
                    'success': True,
                    'session_id': session_id,
                    'user': self.get_user_info(username)
                })
            
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        @self.app.route('/api/auth/register', methods=['POST'])
        def register():
            """ثبت‌نام کاربر"""
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            email = data.get('email')
            
            if self.create_user(username, password, email):
                return jsonify({'success': True})
            
            return jsonify({'success': False, 'error': 'User already exists'}), 400
        
        @self.app.route('/api/user/profile')
        def profile():
            """پروفایل کاربر"""
            if not self.is_authenticated():
                return jsonify({'error': 'Not authenticated'}), 401
            
            user_info = self.get_user_info(session.get('username'))
            traffic_stats = self.get_user_traffic_stats(user_info['id'])
            
            return jsonify({
                'user': user_info,
                'traffic': traffic_stats
            })
        
        @self.app.route('/api/admin/users')
        def admin_users():
            """مدیریت کاربران (فقط ادمین)"""
            if not self.is_admin():
                return jsonify({'error': 'Access denied'}), 403
            
            users = self.get_all_users()
            return jsonify({'users': users})
        
        @self.app.route('/api/admin/statistics')
        def admin_statistics():
            """آمار کلی (فقط ادمین)"""
            if not self.is_admin():
                return jsonify({'error': 'Access denied'}), 403
            
            stats = self.get_system_statistics()
            return jsonify(stats)
        
        @self.app.route('/api/ws/connect')
        def websocket_connect():
            """اتصال WebSocket برای چت"""
            if not self.is_authenticated():
                return jsonify({'error': 'Not authenticated'}), 401
            
            return jsonify({'success': True, 'room': 'general'})
        
        @self.socketio.on('join')
        def on_join(data):
            """پیوستن به اتاق چت"""
            room = data.get('room', 'general')
            join_room(room)
            emit('status', {'msg': f'User joined {room}'}, room=room)
        
        @self.socketio.on('message')
        def on_message(data):
            """ارسال پیام"""
            room = data.get('room', 'general')
            message = data.get('message', '')
            
            # ثبت ترافیک
            self.log_traffic(session.get('user_id'), len(message.encode()), 0)
            
            emit('message', {
                'user': session.get('username'),
                'message': message,
                'timestamp': datetime.now().isoformat()
            }, room=room)
        
        @self.app.route('/api/files/upload', methods=['POST'])
        def upload_file():
            """آپلود فایل"""
            if not self.is_authenticated():
                return jsonify({'error': 'Not authenticated'}), 401
            
            if 'file' not in request.files:
                return jsonify({'error': 'No file'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            # شبیه‌سازی آپلود
            file_size = len(file.read())
            self.log_traffic(session.get('user_id'), file_size, 0)
            
            return jsonify({
                'success': True,
                'file_size': file_size,
                'filename': file.filename
            })
        
        @self.app.route('/api/files/download/<filename>')
        def download_file(filename):
            """دانلود فایل"""
            if not self.is_authenticated():
                return jsonify({'error': 'Not authenticated'}), 401
            
            # شبیه‌سازی دانلود
            file_size = random.randint(1024, 10240)  # 1KB to 10KB
            self.log_traffic(session.get('user_id'), 0, file_size)
            
            return jsonify({
                'success': True,
                'file_size': file_size,
                'filename': filename
            })
        
        @self.app.route('/api/stream/live')
        def live_stream():
            """استریم زنده"""
            if not self.is_authenticated():
                return jsonify({'error': 'Not authenticated'}), 401
            
            # شبیه‌سازی استریم
            stream_data = b"stream_data" * 1000
            self.log_traffic(session.get('user_id'), 0, len(stream_data))
            
            return jsonify({
                'success': True,
                'stream_url': f'https://{self.domain}/stream/live.m3u8'
            })
    
    def authenticate_user(self, username, password):
        """احراز هویت کاربر"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT password_hash FROM users WHERE username = ? AND is_active = 1', (username,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result and check_password_hash(result[0], password):
            # به‌روزرسانی آخرین ورود
            self.update_last_login(username)
            return True
        
        return False
    
    def create_user(self, username, password, email=None):
        """ایجاد کاربر جدید"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            user_uuid = str(uuid.uuid4())
            password_hash = generate_password_hash(password)
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, uuid)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, email, user_uuid))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False
    
    def create_session(self, username):
        """ایجاد جلسه کاربر"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # دریافت ID کاربر
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user_id = cursor.fetchone()[0]
        
        # ایجاد جلسه جدید
        session_id = base64.b64encode(os.urandom(32)).decode()
        expires_at = datetime.now() + timedelta(days=7)
        
        cursor.execute('''
            INSERT INTO sessions (user_id, session_id, expires_at)
            VALUES (?, ?, ?)
        ''', (user_id, session_id, expires_at))
        
        conn.commit()
        conn.close()
        
        return session_id
    
    def is_authenticated(self):
        """بررسی احراز هویت"""
        session_id = request.headers.get('X-Session-ID')
        if not session_id:
            return False
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.id, u.username FROM users u
            JOIN sessions s ON u.id = s.user_id
            WHERE s.session_id = ? AND s.is_active = 1 AND s.expires_at > ?
        ''', (session_id, datetime.now()))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            session['user_id'] = result[0]
            session['username'] = result[1]
            return True
        
        return False
    
    def is_admin(self):
        """بررسی دسترسی ادمین"""
        if not self.is_authenticated():
            return False
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT role FROM users WHERE id = ?', (session.get('user_id'),))
        result = cursor.fetchone()
        conn.close()
        
        return result and result[0] == 'admin'
    
    def log_traffic(self, user_id, bytes_uploaded, bytes_downloaded):
        """ثبت ترافیک کاربر"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO traffic_logs (user_id, bytes_uploaded, bytes_downloaded, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, bytes_uploaded, bytes_downloaded, request.remote_addr, request.headers.get('User-Agent')))
        
        conn.commit()
        conn.close()
    
    def get_user_info(self, username):
        """دریافت اطلاعات کاربر"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, uuid, created_at, last_login, role
            FROM users WHERE username = ?
        ''', (username,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'uuid': result[3],
                'created_at': result[4],
                'last_login': result[5],
                'role': result[6]
            }
        
        return None
    
    def get_user_traffic_stats(self, user_id):
        """دریافت آمار ترافیک کاربر"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # آمار امروز
        cursor.execute('''
            SELECT SUM(bytes_uploaded), SUM(bytes_downloaded), COUNT(*)
            FROM traffic_logs
            WHERE user_id = ? AND DATE(timestamp) = DATE('now')
        ''', (user_id,))
        
        today_stats = cursor.fetchone()
        
        # آمار کل
        cursor.execute('''
            SELECT SUM(bytes_uploaded), SUM(bytes_downloaded), COUNT(*)
            FROM traffic_logs
            WHERE user_id = ?
        ''', (user_id,))
        
        total_stats = cursor.fetchone()
        
        conn.close()
        
        return {
            'today': {
                'uploaded': today_stats[0] or 0,
                'downloaded': today_stats[1] or 0,
                'sessions': today_stats[2] or 0
            },
            'total': {
                'uploaded': total_stats[0] or 0,
                'downloaded': total_stats[1] or 0,
                'sessions': total_stats[2] or 0
            }
        }
    
    def get_all_users(self):
        """دریافت لیست تمام کاربران"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, created_at, last_login, is_active, role
            FROM users ORDER BY created_at DESC
        ''')
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'created_at': row[3],
                'last_login': row[4],
                'is_active': bool(row[5]),
                'role': row[6]
            })
        
        conn.close()
        return users
    
    def get_system_statistics(self):
        """دریافت آمار کلی سیستم"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # تعداد کاربران
        cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
        total_users = cursor.fetchone()[0]
        
        # کاربران فعال امروز
        cursor.execute('''
            SELECT COUNT(DISTINCT user_id) FROM traffic_logs
            WHERE DATE(timestamp) = DATE('now')
        ''')
        active_users = cursor.fetchone()[0]
        
        # ترافیک امروز
        cursor.execute('''
            SELECT SUM(bytes_uploaded + bytes_downloaded)
            FROM traffic_logs
            WHERE DATE(timestamp) = DATE('now')
        ''')
        total_traffic = cursor.fetchone()[0] or 0
        
        # جلسات امروز
        cursor.execute('''
            SELECT COUNT(*) FROM traffic_logs
            WHERE DATE(timestamp) = DATE('now')
        ''')
        total_sessions = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_users': total_users,
            'active_users': active_users,
            'total_traffic': total_traffic,
            'total_sessions': total_sessions,
            'date': datetime.now().date().isoformat()
        }
    
    def update_last_login(self, username):
        """به‌روزرسانی آخرین ورود"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET last_login = CURRENT_TIMESTAMP
            WHERE username = ?
        ''', (username,))
        
        conn.commit()
        conn.close()
    
    def generate_client_config(self, username):
        """تولید پیکربندی کلاینت برای کاربر"""
        user_info = self.get_user_info(username)
        if not user_info:
            return None
        
        config = {
            "server": self.domain,
            "server_port": self.port,
            "uuid": user_info['uuid'],
            "alter_id": 0,
            "security": "tls",
            "network": "ws",
            "ws_opts": {
                "path": self.v2ray_path,
                "headers": {
                    "Host": self.domain
                }
            }
        }
        
        return config
    
    def run(self, host='0.0.0.0', port=80, debug=False):
        """اجرای سرور"""
        print(f"🚀 راه‌اندازی شبیه‌ساز ترافیک روی {host}:{port}")
        print(f"🌐 دامنه: {self.domain}")
        print(f"🔑 UUID ثابت: {self.v2ray_uuid}")
        print(f"🛣️ مسیر ثابت: {self.v2ray_path}")
        
        self.socketio.run(self.app, host=host, port=port, debug=debug)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='شبیه‌ساز ترافیک واقعی v2ray')
    parser.add_argument('--domain', required=True, help='دامنه سرور')
    parser.add_argument('--port', type=int, default=80, help='پورت وب سرور')
    parser.add_argument('--v2ray-port', type=int, default=443, help='پورت v2ray')
    parser.add_argument('--debug', action='store_true', help='حالت دیباگ')
    
    args = parser.parse_args()
    
    simulator = RealisticTrafficSimulator(args.domain, args.v2ray_port)
    simulator.run(port=args.port, debug=args.debug)

if __name__ == "__main__":
    main() 