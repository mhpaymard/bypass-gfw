#!/usr/bin/env python3
"""
Advanced Monitoring System
Monitors traffic patterns and detects potential threats
"""

import asyncio
import json
import random
import time
import hashlib
import base64
import uuid
import logging
import psutil
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp
from aiohttp import web
import numpy as np
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TrafficMetrics:
    """Traffic metrics structure"""
    timestamp: datetime
    bytes_sent: int
    bytes_received: int
    connections: int
    requests_per_second: float
    avg_response_time: float
    error_rate: float
    unique_ips: int
    top_endpoints: List[str]

@dataclass
class SecurityEvent:
    """Security event structure"""
    id: str
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str
    description: str
    action_taken: str
    metadata: Dict[str, Any]

@dataclass
class UserActivity:
    """User activity structure"""
    user_id: str
    timestamp: datetime
    action: str
    endpoint: str
    bytes_transferred: int
    session_duration: float
    user_agent: str
    ip_address: str

class AdvancedMonitor:
    """Advanced monitoring system with threat detection"""
    
    def __init__(self):
        self.traffic_history: deque = deque(maxlen=10000)
        self.security_events: List[SecurityEvent] = []
        self.user_activities: List[UserActivity] = []
        self.anomaly_detectors: Dict[str, Any] = {}
        self.threat_patterns: Dict[str, List[str]] = {}
        
        # Performance metrics
        self.performance_metrics = {
            "cpu_usage": [],
            "memory_usage": [],
            "disk_usage": [],
            "network_io": [],
            "active_connections": []
        }
        
        # Security thresholds
        self.security_thresholds = {
            "max_requests_per_minute": 1000,
            "max_connections_per_ip": 100,
            "max_error_rate": 0.1,
            "max_response_time": 5000,
            "suspicious_patterns": [
                "sqlmap", "nikto", "nmap", "dirb", "gobuster",
                "admin", "wp-admin", "phpmyadmin", "shell",
                "eval(", "exec(", "system(", "passthru("
            ]
        }
        
        # Initialize database
        self.db_path = Path("monitoring.db")
        self.init_database()
        
        # Initialize anomaly detectors
        self.init_anomaly_detectors()
        
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                connections INTEGER,
                requests_per_second REAL,
                avg_response_time REAL,
                error_rate REAL,
                unique_ips INTEGER,
                top_endpoints TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                description TEXT,
                action_taken TEXT,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                endpoint TEXT,
                bytes_transferred INTEGER,
                session_duration REAL,
                user_agent TEXT,
                ip_address TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                value REAL,
                metadata TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
        logger.info("Database initialized")
    
    def init_anomaly_detectors(self):
        """Initialize anomaly detection algorithms"""
        # Simple statistical anomaly detector
        self.anomaly_detectors["statistical"] = {
            "window_size": 100,
            "threshold": 2.0,  # Standard deviations
            "history": deque(maxlen=100)
        }
        
        # Pattern-based detector
        self.anomaly_detectors["pattern"] = {
            "suspicious_patterns": set(self.security_thresholds["suspicious_patterns"]),
            "rate_limits": defaultdict(list)
        }
        
        # Behavioral detector
        self.anomaly_detectors["behavioral"] = {
            "user_profiles": {},
            "session_patterns": defaultdict(list)
        }
    
    async def record_traffic_metrics(self, metrics: TrafficMetrics):
        """Record traffic metrics"""
        self.traffic_history.append(metrics)
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO traffic_metrics 
            (timestamp, bytes_sent, bytes_received, connections, requests_per_second, 
             avg_response_time, error_rate, unique_ips, top_endpoints)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics.timestamp.isoformat(),
            metrics.bytes_sent,
            metrics.bytes_received,
            metrics.connections,
            metrics.requests_per_second,
            metrics.avg_response_time,
            metrics.error_rate,
            metrics.unique_ips,
            json.dumps(metrics.top_endpoints)
        ))
        
        conn.commit()
        conn.close()
        
        # Check for anomalies
        await self.detect_anomalies(metrics)
    
    async def record_security_event(self, event: SecurityEvent):
        """Record security event"""
        self.security_events.append(event)
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events 
            (id, timestamp, event_type, severity, source_ip, description, action_taken, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.id,
            event.timestamp.isoformat(),
            event.event_type,
            event.severity,
            event.source_ip,
            event.description,
            event.action_taken,
            json.dumps(event.metadata)
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"Security event: {event.event_type} - {event.description}")
    
    async def record_user_activity(self, activity: UserActivity):
        """Record user activity"""
        self.user_activities.append(activity)
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO user_activities 
            (user_id, timestamp, action, endpoint, bytes_transferred, session_duration, user_agent, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            activity.user_id,
            activity.timestamp.isoformat(),
            activity.action,
            activity.endpoint,
            activity.bytes_transferred,
            activity.session_duration,
            activity.user_agent,
            activity.ip_address
        ))
        
        conn.commit()
        conn.close()
        
        # Update behavioral profile
        await self.update_behavioral_profile(activity)
    
    async def record_performance_metrics(self):
        """Record system performance metrics"""
        timestamp = datetime.now()
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        self.performance_metrics["cpu_usage"].append(cpu_percent)
        
        # Memory usage
        memory = psutil.virtual_memory()
        self.performance_metrics["memory_usage"].append(memory.percent)
        
        # Disk usage
        disk = psutil.disk_usage('/')
        self.performance_metrics["disk_usage"].append(disk.percent)
        
        # Network I/O
        network = psutil.net_io_counters()
        self.performance_metrics["network_io"].append({
            "bytes_sent": network.bytes_sent,
            "bytes_recv": network.bytes_recv
        })
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for metric_type, value in [
            ("cpu_usage", cpu_percent),
            ("memory_usage", memory.percent),
            ("disk_usage", disk.percent)
        ]:
            cursor.execute('''
                INSERT INTO performance_metrics (timestamp, metric_type, value, metadata)
                VALUES (?, ?, ?, ?)
            ''', (
                timestamp.isoformat(),
                metric_type,
                value,
                json.dumps({})
            ))
        
        conn.commit()
        conn.close()
    
    async def detect_anomalies(self, metrics: TrafficMetrics):
        """Detect anomalies in traffic patterns"""
        # Statistical anomaly detection
        await self.statistical_anomaly_detection(metrics)
        
        # Pattern-based detection
        await self.pattern_anomaly_detection(metrics)
        
        # Behavioral anomaly detection
        await self.behavioral_anomaly_detection(metrics)
    
    async def statistical_anomaly_detection(self, metrics: TrafficMetrics):
        """Statistical anomaly detection using moving averages"""
        detector = self.anomaly_detectors["statistical"]
        history = detector["history"]
        
        # Add current metrics to history
        history.append({
            "requests_per_second": metrics.requests_per_second,
            "avg_response_time": metrics.avg_response_time,
            "error_rate": metrics.error_rate
        })
        
        if len(history) < detector["window_size"]:
            return
        
        # Calculate statistics
        rps_values = [h["requests_per_second"] for h in history]
        response_times = [h["avg_response_time"] for h in history]
        error_rates = [h["error_rate"] for h in history]
        
        # Check for anomalies
        threshold = detector["threshold"]
        
        for metric_name, values in [
            ("requests_per_second", rps_values),
            ("avg_response_time", response_times),
            ("error_rate", error_rates)
        ]:
            mean = np.mean(values[:-1])  # Exclude current value
            std = np.std(values[:-1])
            
            if std > 0:
                z_score = abs(values[-1] - mean) / std
                
                if z_score > threshold:
                    await self.create_security_event(
                        event_type="statistical_anomaly",
                        severity="medium",
                        source_ip="system",
                        description=f"Anomaly detected in {metric_name}: z-score={z_score:.2f}",
                        action_taken="monitoring",
                        metadata={
                            "metric": metric_name,
                            "z_score": z_score,
                            "current_value": values[-1],
                            "mean": mean,
                            "std": std
                        }
                    )
    
    async def pattern_anomaly_detection(self, metrics: TrafficMetrics):
        """Pattern-based anomaly detection"""
        detector = self.anomaly_detectors["pattern"]
        
        # Check for suspicious patterns in endpoints
        for endpoint in metrics.top_endpoints:
            endpoint_lower = endpoint.lower()
            
            for pattern in detector["suspicious_patterns"]:
                if pattern.lower() in endpoint_lower:
                    await self.create_security_event(
                        event_type="suspicious_pattern",
                        severity="high",
                        source_ip="unknown",
                        description=f"Suspicious pattern detected: {pattern} in {endpoint}",
                        action_taken="blocked",
                        metadata={
                            "pattern": pattern,
                            "endpoint": endpoint
                        }
                    )
        
        # Check rate limits
        current_time = time.time()
        rate_limits = detector["rate_limits"]
        
        # Clean old entries
        for key in list(rate_limits.keys()):
            rate_limits[key] = [t for t in rate_limits[key] if current_time - t < 60]
        
        # Check if any IP has exceeded limits
        for ip, timestamps in rate_limits.items():
            if len(timestamps) > self.security_thresholds["max_requests_per_minute"]:
                await self.create_security_event(
                    event_type="rate_limit_exceeded",
                    severity="medium",
                    source_ip=ip,
                    description=f"Rate limit exceeded: {len(timestamps)} requests in 1 minute",
                    action_taken="throttled",
                    metadata={
                        "requests_count": len(timestamps),
                        "time_window": 60
                    }
                )
    
    async def behavioral_anomaly_detection(self, metrics: TrafficMetrics):
        """Behavioral anomaly detection"""
        detector = self.anomaly_detectors["behavioral"]
        
        # Analyze user behavior patterns
        recent_activities = [
            activity for activity in self.user_activities
            if (datetime.now() - activity.timestamp).total_seconds() < 3600  # Last hour
        ]
        
        # Group by user
        user_activities = defaultdict(list)
        for activity in recent_activities:
            user_activities[activity.user_id].append(activity)
        
        # Check for unusual behavior
        for user_id, activities in user_activities.items():
            if user_id not in detector["user_profiles"]:
                detector["user_profiles"][user_id] = {
                    "avg_session_duration": 0,
                    "common_endpoints": set(),
                    "usual_times": set()
                }
            
            profile = detector["user_profiles"][user_id]
            
            # Check session duration
            session_durations = [a.session_duration for a in activities]
            avg_duration = np.mean(session_durations)
            
            if profile["avg_session_duration"] > 0:
                duration_diff = abs(avg_duration - profile["avg_session_duration"])
                if duration_diff > profile["avg_session_duration"] * 2:  # 200% difference
                    await self.create_security_event(
                        event_type="behavioral_anomaly",
                        severity="low",
                        source_ip="unknown",
                        description=f"Unusual session duration for user {user_id}",
                        action_taken="monitoring",
                        metadata={
                            "user_id": user_id,
                            "current_avg_duration": avg_duration,
                            "usual_avg_duration": profile["avg_session_duration"]
                        }
                    )
            
            # Update profile
            profile["avg_session_duration"] = avg_duration
            profile["common_endpoints"].update([a.endpoint for a in activities])
            profile["usual_times"].add(activities[0].timestamp.hour)
    
    async def update_behavioral_profile(self, activity: UserActivity):
        """Update user behavioral profile"""
        detector = self.anomaly_detectors["behavioral"]
        
        if activity.user_id not in detector["user_profiles"]:
            detector["user_profiles"][activity.user_id] = {
                "avg_session_duration": 0,
                "common_endpoints": set(),
                "usual_times": set(),
                "activity_count": 0
            }
        
        profile = detector["user_profiles"][activity.user_id]
        profile["activity_count"] += 1
        
        # Update session patterns
        detector["session_patterns"][activity.user_id].append({
            "timestamp": activity.timestamp,
            "action": activity.action,
            "endpoint": activity.endpoint,
            "duration": activity.session_duration
        })
        
        # Keep only recent patterns
        detector["session_patterns"][activity.user_id] = detector["session_patterns"][activity.user_id][-100:]
    
    async def create_security_event(self, event_type: str, severity: str, 
                                  source_ip: str, description: str, 
                                  action_taken: str, metadata: Dict[str, Any]):
        """Create a security event"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            description=description,
            action_taken=action_taken,
            metadata=metadata
        )
        
        await self.record_security_event(event)
    
    async def get_traffic_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get traffic summary for the last N hours"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get metrics from last N hours
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute('''
            SELECT * FROM traffic_metrics 
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
        ''', (cutoff_time,))
        
        rows = cursor.fetchall()
        
        if not rows:
            return {"error": "No data available"}
        
        # Calculate summary statistics
        metrics = []
        for row in rows:
            metrics.append({
                "timestamp": row[1],
                "bytes_sent": row[2],
                "bytes_received": row[3],
                "connections": row[4],
                "requests_per_second": row[5],
                "avg_response_time": row[6],
                "error_rate": row[7],
                "unique_ips": row[8]
            })
        
        # Calculate totals and averages
        total_bytes_sent = sum(m["bytes_sent"] for m in metrics)
        total_bytes_received = sum(m["bytes_received"] for m in metrics)
        avg_requests_per_second = np.mean([m["requests_per_second"] for m in metrics])
        avg_response_time = np.mean([m["avg_response_time"] for m in metrics])
        avg_error_rate = np.mean([m["error_rate"] for m in metrics])
        
        conn.close()
        
        return {
            "period_hours": hours,
            "total_bytes_sent": total_bytes_sent,
            "total_bytes_received": total_bytes_received,
            "avg_requests_per_second": avg_requests_per_second,
            "avg_response_time": avg_response_time,
            "avg_error_rate": avg_error_rate,
            "total_connections": sum(m["connections"] for m in metrics),
            "unique_ips_count": max(m["unique_ips"] for m in metrics) if metrics else 0
        }
    
    async def get_security_events(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get security events from the last N hours"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute('''
            SELECT * FROM security_events 
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
        ''', (cutoff_time,))
        
        rows = cursor.fetchall()
        
        events = []
        for row in rows:
            events.append({
                "id": row[0],
                "timestamp": row[1],
                "event_type": row[2],
                "severity": row[3],
                "source_ip": row[4],
                "description": row[5],
                "action_taken": row[6],
                "metadata": json.loads(row[7]) if row[7] else {}
            })
        
        conn.close()
        return events
    
    async def get_performance_metrics(self, hours: int = 24) -> Dict[str, List[float]]:
        """Get performance metrics from the last N hours"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        metrics = {
            "cpu_usage": [],
            "memory_usage": [],
            "disk_usage": []
        }
        
        for metric_type in metrics.keys():
            cursor.execute('''
                SELECT value FROM performance_metrics 
                WHERE metric_type = ? AND timestamp >= ?
                ORDER BY timestamp DESC
            ''', (metric_type, cutoff_time))
            
            values = [row[0] for row in cursor.fetchall()]
            metrics[metric_type] = values
        
        conn.close()
        return metrics
    
    async def start_monitoring(self):
        """Start the monitoring system"""
        logger.info("Starting advanced monitoring system")
        
        # Start background tasks
        asyncio.create_task(self.performance_monitor())
        asyncio.create_task(self.cleanup_old_data())
        
        logger.info("Advanced monitoring system started")
    
    async def performance_monitor(self):
        """Background task for performance monitoring"""
        while True:
            try:
                await self.record_performance_metrics()
                await asyncio.sleep(60)  # Record every minute
            except Exception as e:
                logger.error(f"Error in performance monitor: {e}")
                await asyncio.sleep(60)
    
    async def cleanup_old_data(self):
        """Background task for cleaning old data"""
        while True:
            try:
                # Keep only last 30 days of data
                cutoff_time = (datetime.now() - timedelta(days=30)).isoformat()
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Clean old traffic metrics
                cursor.execute('DELETE FROM traffic_metrics WHERE timestamp < ?', (cutoff_time,))
                
                # Clean old security events (keep high severity events longer)
                cursor.execute('''
                    DELETE FROM security_events 
                    WHERE timestamp < ? AND severity != 'high'
                ''', (cutoff_time,))
                
                # Clean old user activities
                cursor.execute('DELETE FROM user_activities WHERE timestamp < ?', (cutoff_time,))
                
                # Clean old performance metrics
                cursor.execute('DELETE FROM performance_metrics WHERE timestamp < ?', (cutoff_time,))
                
                conn.commit()
                conn.close()
                
                logger.info("Cleaned up old monitoring data")
                
                await asyncio.sleep(3600)  # Clean up every hour
                
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(3600)

async def main():
    """Main function for testing"""
    monitor = AdvancedMonitor()
    await monitor.start_monitoring()
    
    # Simulate some traffic metrics
    for i in range(10):
        metrics = TrafficMetrics(
            timestamp=datetime.now(),
            bytes_sent=random.randint(1000, 10000),
            bytes_received=random.randint(1000, 10000),
            connections=random.randint(10, 100),
            requests_per_second=random.uniform(1, 10),
            avg_response_time=random.uniform(50, 500),
            error_rate=random.uniform(0, 0.05),
            unique_ips=random.randint(5, 50),
            top_endpoints=["/api/v1/users", "/static/css", "/api/v1/analytics"]
        )
        
        await monitor.record_traffic_metrics(metrics)
        await asyncio.sleep(1)
    
    # Get summary
    summary = await monitor.get_traffic_summary(1)
    print("Traffic Summary:", json.dumps(summary, indent=2))
    
    # Keep running
    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        logger.info("Shutting down...")

if __name__ == "__main__":
    asyncio.run(main()) 