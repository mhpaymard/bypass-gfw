#!/usr/bin/env node

/**
 * شبیه‌ساز ترافیک واقعی با Node.js
 * برای شبیه‌سازی کامل وب‌سایت و ترافیک طبیعی
 */

const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

class TrafficSimulator {
    constructor(domain, options = {}) {
        this.domain = domain;
        this.port = options.port || 80;
        this.sslPort = options.sslPort || 443;
        this.v2rayPort = options.v2rayPort || 443;
        this.dbPath = '/var/lib/v2ray/users.db';
        this.jwtSecret = process.env.JWT_SECRET || 'your-secret-key';
        
        this.app = express();
        this.setupMiddleware();
        this.setupDatabase();
        this.setupRoutes();
        this.setupV2Ray();
        
        // تنظیمات CDN
        this.cdnEnabled = options.cdnEnabled !== false;
        this.cdnFallback = options.cdnFallback !== false;
    }
    
    setupMiddleware() {
        // امنیت
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
                    scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'", "wss:", "https:"]
                }
            }
        }));
        
        // CORS
        this.app.use(cors({
            origin: [`https://${this.domain}`, `http://${this.domain}`],
            credentials: true
        }));
        
        // Rate limiting
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 دقیقه
            max: 100, // حداکثر 100 درخواست
            message: 'Too many requests from this IP'
        });
        this.app.use('/api/', limiter);
        
        // Compression
        this.app.use(compression());
        
        // Logging
        this.app.use(morgan('combined'));
        
        // Body parsing
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true }));
        
        // Static files
        this.app.use(express.static(path.join(__dirname, 'public')));
    }
    
    setupDatabase() {
        // ایجاد دایرکتوری
        const dbDir = path.dirname(this.dbPath);
        if (!fs.existsSync(dbDir)) {
            fs.mkdirSync(dbDir, { recursive: true });
        }
        
        this.db = new sqlite3.Database(this.dbPath);
        
        // ایجاد جداول
        this.db.serialize(() => {
            // جدول کاربران
            this.db.run(`
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    uuid TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    role TEXT DEFAULT 'user',
                    traffic_limit BIGINT DEFAULT 1073741824,
                    traffic_used BIGINT DEFAULT 0
                )
            `);
            
            // جدول ترافیک
            this.db.run(`
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    bytes_uploaded BIGINT DEFAULT 0,
                    bytes_downloaded BIGINT DEFAULT 0,
                    session_duration INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    endpoint TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            `);
            
            // جدول جلسات
            this.db.run(`
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    session_token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            `);
            
            // جدول آمار
            this.db.run(`
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE UNIQUE,
                    total_users INTEGER DEFAULT 0,
                    active_users INTEGER DEFAULT 0,
                    total_traffic BIGINT DEFAULT 0,
                    total_sessions INTEGER DEFAULT 0,
                    peak_concurrent INTEGER DEFAULT 0
                )
            `);
            
            // جدول فایل‌ها
            this.db.run(`
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    filename TEXT NOT NULL,
                    file_size BIGINT NOT NULL,
                    file_type TEXT,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    download_count INTEGER DEFAULT 0,
                    is_public BOOLEAN DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            `);
        });
    }
    
    setupRoutes() {
        // صفحه اصلی
        this.app.get('/', (req, res) => {
            res.send(`
                <!DOCTYPE html>
                <html lang="fa" dir="rtl">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>${this.domain} - سرویس ابری</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                    <style>
                        body { font-family: 'Tahoma', sans-serif; }
                        .hero { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
                    </style>
                </head>
                <body>
                    <div class="hero text-white py-5">
                        <div class="container">
                            <h1 class="display-4">به ${this.domain} خوش آمدید</h1>
                            <p class="lead">سرویس ابری پیشرفته با امنیت بالا</p>
                            <a href="/login" class="btn btn-light btn-lg">ورود</a>
                            <a href="/register" class="btn btn-outline-light btn-lg">ثبت‌نام</a>
                        </div>
                    </div>
                    
                    <div class="container my-5">
                        <div class="row">
                            <div class="col-md-4">
                                <h3>🔒 امنیت بالا</h3>
                                <p>رمزنگاری پیشرفته و محافظت از داده‌ها</p>
                            </div>
                            <div class="col-md-4">
                                <h3>⚡ سرعت بالا</h3>
                                <p>سرورهای پرسرعت و بهینه‌سازی شده</p>
                            </div>
                            <div class="col-md-4">
                                <h3>📊 آمار دقیق</h3>
                                <p>نظارت کامل بر ترافیک و استفاده</p>
                            </div>
                        </div>
                    </div>
                    
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
                </body>
                </html>
            `);
        });
        
        // API احراز هویت
        this.app.post('/api/auth/login', async (req, res) => {
            try {
                const { username, password } = req.body;
                
                if (!username || !password) {
                    return res.status(400).json({ error: 'نام کاربری و رمز عبور الزامی است' });
                }
                
                const user = await this.authenticateUser(username, password);
                if (!user) {
                    return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' });
                }
                
                const token = jwt.sign(
                    { userId: user.id, username: user.username, role: user.role },
                    this.jwtSecret,
                    { expiresIn: '7d' }
                );
                
                // ثبت جلسه
                await this.createSession(user.id, token, req.ip, req.get('User-Agent'));
                
                // ثبت ترافیکورود
                await this.logTraffic(user.id, 0, 0, req.ip, req.get('User-Agent'), '/api/auth/login');
                
                res.json({
                    success: true,
                    token,
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        role: user.role,
                        traffic_used: user.traffic_used,
                        traffic_limit: user.traffic_limit
                    }
                });
            } catch (error) {
                console.error('Login error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        this.app.post('/api/auth/register', async (req, res) => {
            try {
                const { username, password, email } = req.body;
                
                if (!username || !password) {
                    return res.status(400).json({ error: 'نام کاربری و رمز عبور الزامی است' });
                }
                
                const success = await this.createUser(username, password, email);
                if (!success) {
                    return res.status(400).json({ error: 'کاربر قبلاً وجود دارد' });
                }
                
                res.json({ success: true, message: 'کاربر با موفقیت ایجاد شد' });
            } catch (error) {
                console.error('Register error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        // API کاربر
        this.app.get('/api/user/profile', this.authenticateToken, async (req, res) => {
            try {
                const user = await this.getUserById(req.user.userId);
                const trafficStats = await this.getUserTrafficStats(req.user.userId);
                
                res.json({
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        role: user.role,
                        traffic_used: user.traffic_used,
                        traffic_limit: user.traffic_limit,
                        created_at: user.created_at
                    },
                    traffic: trafficStats
                });
            } catch (error) {
                console.error('Profile error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        // API فایل‌ها
        this.app.post('/api/files/upload', this.authenticateToken, async (req, res) => {
            try {
                // شبیه‌سازی آپلود فایل
                const fileSize = Math.floor(Math.random() * 1000000) + 10000; // 10KB to 1MB
                
                // بررسی محدودیت ترافیک
                const user = await this.getUserById(req.user.userId);
                if (user.traffic_used + fileSize > user.traffic_limit) {
                    return res.status(403).json({ error: 'محدودیت ترافیک' });
                }
                
                // ثبت ترافیک
                await this.logTraffic(req.user.userId, fileSize, 0, req.ip, req.get('User-Agent'), '/api/files/upload');
                await this.updateUserTraffic(req.user.userId, fileSize);
                
                res.json({
                    success: true,
                    file_size: fileSize,
                    message: 'فایل با موفقیت آپلود شد'
                });
            } catch (error) {
                console.error('Upload error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        this.app.get('/api/files/download/:filename', this.authenticateToken, async (req, res) => {
            try {
                const fileSize = Math.floor(Math.random() * 5000000) + 50000; // 50KB to 5MB
                
                // بررسی محدودیت ترافیک
                const user = await this.getUserById(req.user.userId);
                if (user.traffic_used + fileSize > user.traffic_limit) {
                    return res.status(403).json({ error: 'محدودیت ترافیک' });
                }
                
                // ثبت ترافیک
                await this.logTraffic(req.user.userId, 0, fileSize, req.ip, req.get('User-Agent'), '/api/files/download');
                await this.updateUserTraffic(req.user.userId, fileSize);
                
                res.json({
                    success: true,
                    file_size: fileSize,
                    filename: req.params.filename,
                    message: 'دانلود شروع شد'
                });
            } catch (error) {
                console.error('Download error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        // API استریم
        this.app.get('/api/stream/live', this.authenticateToken, async (req, res) => {
            try {
                const streamSize = Math.floor(Math.random() * 10000000) + 100000; // 100KB to 10MB
                
                // بررسی محدودیت ترافیک
                const user = await this.getUserById(req.user.userId);
                if (user.traffic_used + streamSize > user.traffic_limit) {
                    return res.status(403).json({ error: 'محدودیت ترافیک' });
                }
                
                // ثبت ترافیک
                await this.logTraffic(req.user.userId, 0, streamSize, req.ip, req.get('User-Agent'), '/api/stream/live');
                await this.updateUserTraffic(req.user.userId, streamSize);
                
                res.json({
                    success: true,
                    stream_url: `https://${this.domain}/stream/live.m3u8`,
                    stream_size: streamSize
                });
            } catch (error) {
                console.error('Stream error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        // API چت (WebSocket simulation)
        this.app.post('/api/chat/send', this.authenticateToken, async (req, res) => {
            try {
                const { message, room = 'general' } = req.body;
                const messageSize = Buffer.byteLength(message, 'utf8');
                
                // ثبت ترافیک
                await this.logTraffic(req.user.userId, messageSize, 0, req.ip, req.get('User-Agent'), '/api/chat/send');
                
                res.json({
                    success: true,
                    message: 'پیام ارسال شد',
                    room,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.error('Chat error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        // API ادمین
        this.app.get('/api/admin/users', this.authenticateToken, this.requireAdmin, async (req, res) => {
            try {
                const users = await this.getAllUsers();
                res.json({ users });
            } catch (error) {
                console.error('Admin users error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        this.app.get('/api/admin/statistics', this.authenticateToken, this.requireAdmin, async (req, res) => {
            try {
                const stats = await this.getSystemStatistics();
                res.json(stats);
            } catch (error) {
                console.error('Admin stats error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        // API تولید پیکربندی v2ray
        this.app.get('/api/user/config', this.authenticateToken, async (req, res) => {
            try {
                const user = await this.getUserById(req.user.userId);
                const config = this.generateV2RayConfig(user);
                res.json({ config });
            } catch (error) {
                console.error('Config error:', error);
                res.status(500).json({ error: 'خطای سرور' });
            }
        });
        
        // شبیه‌سازی ترافیک طبیعی
        this.app.get('/api/health', (req, res) => {
            res.json({ status: 'ok', timestamp: new Date().toISOString() });
        });
        
        this.app.get('/api/version', (req, res) => {
            res.json({ version: '1.0.0', build: '2024.01.01' });
        });
        
        // شبیه‌سازی API های مختلف
        this.app.get('/api/news', (req, res) => {
            const news = [
                { id: 1, title: 'به‌روزرسانی سیستم', content: 'سیستم جدید راه‌اندازی شد' },
                { id: 2, title: 'افزایش سرعت', content: 'سرعت سرورها افزایش یافت' }
            ];
            res.json({ news });
        });
        
        this.app.get('/api/weather', (req, res) => {
            const weather = {
                temperature: Math.floor(Math.random() * 30) + 10,
                condition: ['آفتابی', 'ابری', 'بارانی'][Math.floor(Math.random() * 3)],
                humidity: Math.floor(Math.random() * 50) + 30
            };
            res.json(weather);
        });
    }
    
    setupV2Ray() {
        // تولید UUID ثابت
        const crypto = require('crypto');
        const seed = crypto.createHash('md5').update(this.domain).digest('hex');
        this.v2rayUuid = require('uuid').v5(seed, require('uuid').NAMESPACE_DNS);
        this.v2rayPath = '/api/v1/ws'; // ثابت
        
        const config = {
            inbounds: [{
                port: this.v2rayPort,
                protocol: 'vmess',
                settings: {
                    clients: [{
                        id: this.v2rayUuid,
                        alterId: 0
                    }]
                },
                streamSettings: {
                    network: 'ws',
                    security: 'tls',
                    wsSettings: {
                        path: this.v2rayPath,
                        headers: {
                            Host: this.domain
                        }
                    },
                    tlsSettings: {
                        serverName: this.domain,
                        fingerprint: 'chrome',
                        alpn: ['h2', 'http/1.1'],
                        certificates: [{
                            certificateFile: `/etc/v2ray/certs/${this.domain}.pem`,
                            keyFile: `/etc/v2ray/certs/${this.domain}.key`
                        }]
                    }
                }
            }],
            outbounds: [{
                protocol: 'freedom',
                settings: {}
            }],
            log: {
                loglevel: 'warning',
                access: '/var/log/v2ray/access.log',
                error: '/var/log/v2ray/error.log'
            }
        };
        
        // ذخیره پیکربندی
        fs.writeFileSync('/etc/v2ray/config.json', JSON.stringify(config, null, 2));
        
        // راه‌اندازی مجدد v2ray
        require('child_process').execSync('systemctl restart v2ray');
    }
    
    // توابع کمکی
    async authenticateUser(username, password) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE username = ? AND is_active = 1',
                [username],
                async (err, row) => {
                    if (err) return reject(err);
                    if (!row) return resolve(null);
                    
                    const isValid = await bcrypt.compare(password, row.password_hash);
                    if (isValid) {
                        // به‌روزرسانی آخرین ورود
                        this.db.run(
                            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                            [row.id]
                        );
                        resolve(row);
                    } else {
                        resolve(null);
                    }
                }
            );
        });
    }
    
    async createUser(username, password, email = null) {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userUuid = require('uuid').v4();
        
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO users (username, password_hash, email, uuid) VALUES (?, ?, ?, ?)',
                [username, hashedPassword, email, userUuid],
                function(err) {
                    if (err) {
                        if (err.code === 'SQLITE_CONSTRAINT') {
                            resolve(false); // کاربر قبلاً وجود دارد
                        } else {
                            reject(err);
                        }
                    } else {
                        resolve(true);
                    }
                }
            );
        });
    }
    
    async createSession(userId, token, ip, userAgent) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);
        
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
                [userId, token, expiresAt.toISOString(), ip, userAgent],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }
    
    async logTraffic(userId, bytesUploaded, bytesDownloaded, ip, userAgent, endpoint) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO traffic_logs (user_id, bytes_uploaded, bytes_downloaded, ip_address, user_agent, endpoint) VALUES (?, ?, ?, ?, ?, ?)',
                [userId, bytesUploaded, bytesDownloaded, ip, userAgent, endpoint],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }
    
    async updateUserTraffic(userId, bytes) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET traffic_used = traffic_used + ? WHERE id = ?',
                [bytes, userId],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }
    
    async getUserById(userId) {
        return new Promise((resolve, reject) => {
            this.db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }
    
    async getUserTrafficStats(userId) {
        return new Promise((resolve, reject) => {
            this.db.get(`
                SELECT 
                    SUM(bytes_uploaded) as total_uploaded,
                    SUM(bytes_downloaded) as total_downloaded,
                    COUNT(*) as total_sessions
                FROM traffic_logs 
                WHERE user_id = ? AND DATE(timestamp) = DATE('now')
            `, [userId], (err, today) => {
                if (err) return reject(err);
                
                this.db.get(`
                    SELECT 
                        SUM(bytes_uploaded) as total_uploaded,
                        SUM(bytes_downloaded) as total_downloaded,
                        COUNT(*) as total_sessions
                    FROM traffic_logs 
                    WHERE user_id = ?
                `, [userId], (err, total) => {
                    if (err) return reject(err);
                    
                    resolve({
                        today: {
                            uploaded: today.total_uploaded || 0,
                            downloaded: today.total_downloaded || 0,
                            sessions: today.total_sessions || 0
                        },
                        total: {
                            uploaded: total.total_uploaded || 0,
                            downloaded: total.total_downloaded || 0,
                            sessions: total.total_sessions || 0
                        }
                    });
                });
            });
        });
    }
    
    async getAllUsers() {
        return new Promise((resolve, reject) => {
            this.db.all(`
                SELECT id, username, email, created_at, last_login, is_active, role, traffic_used, traffic_limit
                FROM users ORDER BY created_at DESC
            `, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }
    
    async getSystemStatistics() {
        return new Promise((resolve, reject) => {
            this.db.get('SELECT COUNT(*) as total FROM users WHERE is_active = 1', (err, users) => {
                if (err) return reject(err);
                
                this.db.get(`
                    SELECT COUNT(DISTINCT user_id) as active FROM traffic_logs
                    WHERE DATE(timestamp) = DATE('now')
                `, (err, active) => {
                    if (err) return reject(err);
                    
                    this.db.get(`
                        SELECT SUM(bytes_uploaded + bytes_downloaded) as traffic FROM traffic_logs
                        WHERE DATE(timestamp) = DATE('now')
                    `, (err, traffic) => {
                        if (err) return reject(err);
                        
                        resolve({
                            total_users: users.total,
                            active_users: active.active,
                            total_traffic: traffic.traffic || 0,
                            date: new Date().toISOString().split('T')[0]
                        });
                    });
                });
            });
        });
    }
    
    generateV2RayConfig(user) {
        return {
            server: this.domain,
            server_port: this.v2rayPort,
            uuid: user.uuid,
            alter_id: 0,
            security: 'tls',
            network: 'ws',
            ws_opts: {
                path: this.v2rayPath,
                headers: {
                    Host: this.domain
                }
            }
        };
    }
    
    // Middleware احراز هویت
    authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'توکن احراز هویت الزامی است' });
        }
        
        jwt.verify(token, this.jwtSecret, (err, user) => {
            if (err) {
                return res.status(403).json({ error: 'توکن نامعتبر است' });
            }
            req.user = user;
            next();
        });
    };
    
    requireAdmin = (req, res, next) => {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'دسترسی ادمین الزامی است' });
        }
        next();
    };
    
    start() {
        console.log(`🚀 راه‌اندازی شبیه‌ساز ترافیک روی پورت ${this.port}`);
        console.log(`🌐 دامنه: ${this.domain}`);
        console.log(`🔑 UUID ثابت: ${this.v2rayUuid}`);
        console.log(`🛣️ مسیر ثابت: ${this.v2rayPath}`);
        console.log(`📊 CDN: ${this.cdnEnabled ? 'فعال' : 'غیرفعال'}`);
        
        // راه‌اندازی HTTP
        this.server = this.app.listen(this.port, () => {
            console.log(`✅ سرور HTTP روی پورت ${this.port} راه‌اندازی شد`);
        });
        
        // راه‌اندازی HTTPS (اگر گواهی موجود باشد)
        const certPath = `/etc/letsencrypt/live/${this.domain}/fullchain.pem`;
        const keyPath = `/etc/letsencrypt/live/${this.domain}/privkey.pem`;
        
        if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
            const httpsOptions = {
                cert: fs.readFileSync(certPath),
                key: fs.readFileSync(keyPath)
            };
            
            this.httpsServer = https.createServer(httpsOptions, this.app);
            this.httpsServer.listen(this.sslPort, () => {
                console.log(`✅ سرور HTTPS روی پورت ${this.sslPort} راه‌اندازی شد`);
            });
        } else {
            console.log(`⚠️ گواهی SSL یافت نشد، فقط HTTP فعال است`);
        }
    }
}

// اجرای برنامه
if (require.main === module) {
    const domain = process.argv[2];
    if (!domain) {
        console.error('لطفاً دامنه را مشخص کنید');
        console.error('مثال: node traffic-simulator-nodejs.js example.com');
        process.exit(1);
    }
    
    const simulator = new TrafficSimulator(domain, {
        port: parseInt(process.argv[3]) || 80,
        sslPort: parseInt(process.argv[4]) || 443,
        v2rayPort: parseInt(process.argv[5]) || 443,
        cdnEnabled: process.argv[6] !== 'false'
    });
    
    simulator.start();
}

module.exports = TrafficSimulator; 