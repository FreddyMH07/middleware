#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database Manager Module
=======================
Enhanced database operations and connection management

This module provides:
- Database connection management
- Buffer operations with retry logic
- Transaction logging
- Data validation and integrity checks

Author: Freddy Mazmur
Company: PT Sahabat Agro Group
"""

import sqlite3
import json
import uuid
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass


@dataclass
class BufferItem:
    """Data class for buffer items"""
    id: Optional[int]
    uuid: str
    payload: Dict
    endpoint: str
    api_key: str
    created_at: str
    retry_count: int
    status: str
    error_message: Optional[str] = None


@dataclass
class RetryConfig:
    """Configuration for retry mechanism"""
    max_retries: int = 3
    base_delay: int = 30  # seconds
    exponential_backoff: bool = True
    max_delay: int = 300  # 5 minutes


class DatabaseManager:
    """Enhanced database manager with improved error handling and features"""
    
    def __init__(self, db_path: str = "agent_data.db"):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with all required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if we need to migrate existing schema
            cursor.execute("PRAGMA table_info(push_buffer)")
            existing_columns = [row[1] for row in cursor.fetchall()]
            
            # If old schema exists, back it up and recreate
            if existing_columns and 'next_retry' not in existing_columns:
                print("Migrating database schema...")
                cursor.execute("ALTER TABLE push_buffer RENAME TO push_buffer_old")
                
            # Create enhanced push_buffer table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS push_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    api_key TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    retry_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    error_message TEXT,
                    last_attempt TIMESTAMP,
                    next_retry TIMESTAMP,
                    priority INTEGER DEFAULT 1,
                    source_table TEXT,
                    record_id TEXT
                )
            ''')
            
            # Migrate data if old table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='push_buffer_old'")
            if cursor.fetchone():
                cursor.execute('''
                    INSERT INTO push_buffer (id, uuid, payload, endpoint, api_key, created_at, retry_count, status)
                    SELECT id, uuid, payload, endpoint, api_key, created_at, retry_count, status
                    FROM push_buffer_old
                ''')
                cursor.execute("DROP TABLE push_buffer_old")
                print("Database migration completed successfully")
            
        except Exception as e:
            print(f"Database initialization error: {e}")
            # If there's an error, create fresh tables
            cursor.execute("DROP TABLE IF EXISTS push_buffer")
            cursor.execute('''
                CREATE TABLE push_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    api_key TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    retry_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    error_message TEXT,
                    last_attempt TIMESTAMP,
                    next_retry TIMESTAMP,
                    priority INTEGER DEFAULT 1,
                    source_table TEXT,
                    record_id TEXT
                )
            ''')
            print("Created fresh database schema")
        
        # Create enhanced activity_log table (moved to logging_manager)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                module TEXT,
                function TEXT,
                line_number INTEGER
            )
        ''')
        
        # Create mapping_templates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mapping_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                table_name TEXT NOT NULL,
                mapping_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                description TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Create transaction_history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transaction_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                table_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                status TEXT NOT NULL,
                records_count INTEGER DEFAULT 0,
                endpoint TEXT,
                api_key_hash TEXT,
                response_code INTEGER,
                response_time REAL,
                error_message TEXT,
                payload_size INTEGER,
                source_uuid TEXT
            )
        ''')
        
        # Create performance_metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                metric_unit TEXT,
                context TEXT
            )
        ''')
        
        # Create configuration_audit table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configuration_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                action TEXT NOT NULL,
                section TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                description TEXT
            )
        ''')
        
        # Create indexes for better performance (with error handling)
        try:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_buffer_status ON push_buffer(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_buffer_next_retry ON push_buffer(next_retry)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_log(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_transaction_timestamp ON transaction_history(timestamp)')
        except Exception as e:
            print(f"Warning: Could not create some indexes: {e}")
        
        conn.commit()
        conn.close()
    
    def add_to_buffer(self, payload: Dict, endpoint: str, api_key: str, 
                     priority: int = 1, source_table: str = "", 
                     record_id: str = "") -> str:
        """
        Add data to push buffer with enhanced metadata
        
        Args:
            payload: Data payload to send
            endpoint: API endpoint
            api_key: API key
            priority: Priority level (1=high, 2=normal, 3=low)
            source_table: Source table name
            record_id: Source record identifier
            
        Returns:
            UUID of the buffer item
        """
        data_uuid = str(uuid.uuid4())
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO push_buffer 
                (uuid, payload, endpoint, api_key, priority, source_table, record_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (data_uuid, json.dumps(payload), endpoint, api_key, 
                  priority, source_table, record_id))
            
            conn.commit()
            return data_uuid
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def get_buffer_items(self, status: str = 'pending', limit: int = 10,
                        priority_order: bool = True) -> List[BufferItem]:
        """
        Get items from buffer with enhanced filtering
        
        Args:
            status: Status filter
            limit: Maximum items to return
            priority_order: Whether to order by priority
            
        Returns:
            List of BufferItem objects
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            base_query = '''
                SELECT id, uuid, payload, endpoint, api_key, created_at, 
                       retry_count, status, error_message, source_table, record_id
                FROM push_buffer 
                WHERE status = ?
            '''
            
            if status == 'pending':
                # Only get items ready for retry
                base_query += ' AND (next_retry IS NULL OR next_retry <= ?)'
                params = [status, datetime.now().isoformat()]
            else:
                params = [status]
            
            if priority_order:
                base_query += ' ORDER BY priority ASC, created_at ASC'
            else:
                base_query += ' ORDER BY created_at ASC'
            
            base_query += ' LIMIT ?'
            params.append(limit)
            
            cursor.execute(base_query, params)
            
            items = []
            for row in cursor.fetchall():
                items.append(BufferItem(
                    id=row[0],
                    uuid=row[1],
                    payload=json.loads(row[2]),
                    endpoint=row[3],
                    api_key=row[4],
                    created_at=row[5],
                    retry_count=row[6],
                    status=row[7],
                    error_message=row[8]
                ))
            
            return items
        finally:
            conn.close()
    
    def update_buffer_status(self, buffer_id: int, status: str, 
                           retry_count: int = None, error_message: str = None,
                           retry_config: RetryConfig = None) -> bool:
        """
        Update buffer item status with retry scheduling
        
        Args:
            buffer_id: Buffer item ID
            status: New status
            retry_count: Updated retry count
            error_message: Error message if failed
            retry_config: Retry configuration
            
        Returns:
            True if update successful
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Calculate next retry time if status is pending and retry_count > 0
            next_retry = None
            if status == 'pending' and retry_count and retry_count > 0:
                if not retry_config:
                    retry_config = RetryConfig()
                
                if retry_config.exponential_backoff:
                    delay = min(
                        retry_config.base_delay * (2 ** (retry_count - 1)),
                        retry_config.max_delay
                    )
                else:
                    delay = retry_config.base_delay
                
                next_retry = (datetime.now() + timedelta(seconds=delay)).isoformat()
            
            # Build update query dynamically
            update_fields = ['status = ?', 'last_attempt = ?']
            params = [status, datetime.now().isoformat()]
            
            if retry_count is not None:
                update_fields.append('retry_count = ?')
                params.append(retry_count)
            
            if error_message is not None:
                update_fields.append('error_message = ?')
                params.append(error_message)
            
            if next_retry is not None:
                update_fields.append('next_retry = ?')
                params.append(next_retry)
            
            params.append(buffer_id)
            
            query = f'''
                UPDATE push_buffer 
                SET {', '.join(update_fields)}
                WHERE id = ?
            '''
            
            cursor.execute(query, params)
            conn.commit()
            
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def get_buffer_statistics(self) -> Dict[str, int]:
        """Get buffer statistics by status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM push_buffer 
                GROUP BY status
            ''')
            
            stats = {}
            for row in cursor.fetchall():
                stats[row[0]] = row[1]
            
            return stats
        finally:
            conn.close()
    
    def cleanup_buffer(self, older_than_days: int = 7, 
                      completed_only: bool = True) -> int:
        """
        Clean up old buffer items
        
        Args:
            older_than_days: Remove items older than this many days
            completed_only: Only remove completed/failed items
            
        Returns:
            Number of items removed
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cutoff_date = (datetime.now() - timedelta(days=older_than_days)).isoformat()
            
            if completed_only:
                cursor.execute('''
                    DELETE FROM push_buffer 
                    WHERE created_at < ? AND status IN ('completed', 'failed')
                ''', (cutoff_date,))
            else:
                cursor.execute('''
                    DELETE FROM push_buffer 
                    WHERE created_at < ?
                ''', (cutoff_date,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            return deleted_count
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def add_transaction_record(self, transaction_id: str, table_name: str,
                             operation: str, status: str, records_count: int = 0,
                             endpoint: str = "", response_code: int = None,
                             response_time: float = None, error_message: str = None,
                             payload_size: int = None, source_uuid: str = None) -> bool:
        """
        Add transaction history record
        
        Args:
            transaction_id: Unique transaction ID
            table_name: Source table name
            operation: Operation type (push, test, etc.)
            status: Transaction status
            records_count: Number of records processed
            endpoint: API endpoint used
            response_code: HTTP response code
            response_time: Response time in seconds
            error_message: Error message if any
            payload_size: Size of payload in bytes
            source_uuid: Source buffer UUID
            
        Returns:
            True if successful
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Hash API key for security (don't store full key)
            api_key_hash = None
            if endpoint:
                import hashlib
                api_key_hash = hashlib.sha256(endpoint.encode()).hexdigest()[:16]
            
            cursor.execute('''
                INSERT INTO transaction_history 
                (transaction_id, table_name, operation, status, records_count,
                 endpoint, api_key_hash, response_code, response_time, 
                 error_message, payload_size, source_uuid)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (transaction_id, table_name, operation, status, records_count,
                  endpoint, api_key_hash, response_code, response_time,
                  error_message, payload_size, source_uuid))
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def get_transaction_history(self, limit: int = 100, 
                              start_date: str = None, end_date: str = None,
                              status_filter: str = None) -> List[Dict]:
        """
        Get transaction history with filtering
        
        Args:
            limit: Maximum records to return
            start_date: Start date filter (YYYY-MM-DD)
            end_date: End date filter (YYYY-MM-DD)
            status_filter: Status filter
            
        Returns:
            List of transaction records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            query = '''
                SELECT transaction_id, timestamp, table_name, operation, status,
                       records_count, endpoint, response_code, response_time,
                       error_message, payload_size
                FROM transaction_history
                WHERE 1=1
            '''
            params = []
            
            if start_date:
                query += ' AND date(timestamp) >= ?'
                params.append(start_date)
            
            if end_date:
                query += ' AND date(timestamp) <= ?'
                params.append(end_date)
            
            if status_filter:
                query += ' AND status = ?'
                params.append(status_filter)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            
            transactions = []
            for row in cursor.fetchall():
                transactions.append({
                    'transaction_id': row[0],
                    'timestamp': row[1],
                    'table_name': row[2],
                    'operation': row[3],
                    'status': row[4],
                    'records_count': row[5],
                    'endpoint': row[6],
                    'response_code': row[7],
                    'response_time': row[8],
                    'error_message': row[9],
                    'payload_size': row[10]
                })
            
            return transactions
        finally:
            conn.close()
    
    def get_transaction_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get transaction statistics for specified time period
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            
            # Status counts
            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM transaction_history 
                WHERE timestamp > ?
                GROUP BY status
            ''', (cutoff_time,))
            
            status_counts = {}
            for row in cursor.fetchall():
                status_counts[row[0]] = row[1]
            
            # Average response time
            cursor.execute('''
                SELECT AVG(response_time) as avg_response_time
                FROM transaction_history 
                WHERE timestamp > ? AND response_time IS NOT NULL
            ''', (cutoff_time,))
            
            avg_response_time = cursor.fetchone()[0] or 0
            
            # Total records processed
            cursor.execute('''
                SELECT SUM(records_count) as total_records
                FROM transaction_history 
                WHERE timestamp > ?
            ''', (cutoff_time,))
            
            total_records = cursor.fetchone()[0] or 0
            
            return {
                'status_counts': status_counts,
                'avg_response_time': round(avg_response_time, 2),
                'total_records': total_records,
                'period_hours': hours
            }
        finally:
            conn.close()
    
    def record_performance_metric(self, metric_name: str, metric_value: float,
                                 metric_unit: str = "", context: str = "") -> bool:
        """
        Record a performance metric
        
        Args:
            metric_name: Name of the metric
            metric_value: Metric value
            metric_unit: Unit of measurement
            context: Additional context
            
        Returns:
            True if successful
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO performance_metrics 
                (metric_name, metric_value, metric_unit, context)
                VALUES (?, ?, ?, ?)
            ''', (metric_name, metric_value, metric_unit, context))
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def get_performance_metrics(self, metric_name: str = None, 
                               hours: int = 24) -> List[Dict]:
        """
        Get performance metrics
        
        Args:
            metric_name: Specific metric name filter
            hours: Hours to look back
            
        Returns:
            List of metric records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            
            if metric_name:
                cursor.execute('''
                    SELECT timestamp, metric_name, metric_value, metric_unit, context
                    FROM performance_metrics 
                    WHERE metric_name = ? AND timestamp > ?
                    ORDER BY timestamp DESC
                ''', (metric_name, cutoff_time))
            else:
                cursor.execute('''
                    SELECT timestamp, metric_name, metric_value, metric_unit, context
                    FROM performance_metrics 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                ''', (cutoff_time,))
            
            metrics = []
            for row in cursor.fetchall():
                metrics.append({
                    'timestamp': row[0],
                    'metric_name': row[1],
                    'metric_value': row[2],
                    'metric_unit': row[3],
                    'context': row[4]
                })
            
            return metrics
        finally:
            conn.close()


class ConnectionManager:
    """Manages database connections with connection pooling and health checks"""
    
    def __init__(self):
        self.connections = {}
        self.health_status = {}
    
    def test_connection(self, conn_string: str, test_query: str = None) -> Dict[str, Any]:
        """
        Test database connection with detailed results
        
        Args:
            conn_string: Database connection string
            test_query: Optional test query
            
        Returns:
            Dictionary with test results
        """
        import pyodbc
        import time
        
        result = {
            'success': False,
            'response_time': 0,
            'error': None,
            'details': []
        }
        
        start_time = time.time()
        
        try:
            # Test basic connection
            conn = pyodbc.connect(conn_string, timeout=10)
            result['details'].append("[OK] Connection: Established successfully")
            
            # Test cursor creation
            cursor = conn.cursor()
            result['details'].append("[OK] Cursor: Created successfully")
            
            # Test basic query
            cursor.execute("SELECT 1")
            cursor.fetchone()
            result['details'].append("[OK] Query: Basic query executed")
            
            # Test custom query if provided
            if test_query:
                try:
                    cursor.execute(test_query)
                    cursor.fetchone()
                    result['details'].append("[OK] Custom Query: Executed successfully")
                except Exception as e:
                    result['details'].append(f"[WARN][CHAR] Custom Query: Failed - {str(e)}")
            
            conn.close()
            result['success'] = True
            
        except Exception as e:
            result['error'] = str(e)
            result['details'].append(f"[ERROR] Connection: Failed - {str(e)}")
        
        result['response_time'] = round((time.time() - start_time) * 1000, 2)
        return result
