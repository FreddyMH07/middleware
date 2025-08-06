#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Logging Manager Module
======================
Centralized logging functionality for MDB Agent Pro

This module provides:
- Unified logging to file and database
- Log level management
- Structured log entries
- Log rotation and cleanup

Author: Freddy Mazmur
Company: PT Sahabat Agro Group
"""

import logging
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path


class LogManager:
    """Centralized logging manager for consistent log handling"""
    
    def __init__(self, db_path: str = "agent_data.db", log_file: str = "agent.log"):
        """
        Initialize log manager
        
        Args:
            db_path: Path to SQLite database
            log_file: Path to log file
        """
        self.db_path = db_path
        self.log_file = log_file
        self.setup_logging()
        self.setup_database()
    
    def setup_logging(self):
        """Setup file logging configuration"""
        # Remove existing handlers to avoid duplicates
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def setup_database(self):
        """Ensure database tables exist for logging"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if we need to migrate existing activity_log schema
            cursor.execute("PRAGMA table_info(activity_log)")
            existing_columns = [row[1] for row in cursor.fetchall()]
            
            # If old schema exists, back it up and recreate
            if existing_columns and 'module' not in existing_columns:
                print("Migrating activity_log schema...")
                cursor.execute("ALTER TABLE activity_log RENAME TO activity_log_old")
                
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
            
            # Migrate data if old table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='activity_log_old'")
            if cursor.fetchone():
                cursor.execute('''
                    INSERT INTO activity_log (id, timestamp, level, message, details)
                    SELECT id, timestamp, level, message, details
                    FROM activity_log_old
                ''')
                cursor.execute("DROP TABLE activity_log_old")
                print("Activity log migration completed successfully")
                
        except Exception as e:
            print(f"Database setup error: {e}")
            # If there's an error, create fresh table
            cursor.execute("DROP TABLE IF EXISTS activity_log")
            cursor.execute('''
                CREATE TABLE activity_log (
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
            print("Created fresh activity_log schema")
        
        conn.commit()
        conn.close()
    
    def log(self, level: str, message: str, details: str = "", 
            module: str = "", function: str = "", line_number: int = 0) -> None:
        """
        Unified logging method
        
        Args:
            level: Log level (INFO, WARNING, ERROR, DEBUG, SUCCESS)
            message: Main log message
            details: Additional details
            module: Module name where log occurred
            function: Function name where log occurred
            line_number: Line number where log occurred
        """
        # Clean message for file logging (remove emojis that might cause encoding issues)
        clean_message = self._clean_message(message)
        
        # Log to file
        if level == "ERROR":
            self.logger.error(clean_message)
        elif level == "WARNING":
            self.logger.warning(clean_message)
        elif level == "DEBUG":
            self.logger.debug(clean_message)
        else:
            self.logger.info(clean_message)
        
        # Log to database
        self._log_to_database(level, message, details, module, function, line_number)
    
    def _clean_message(self, message: str) -> str:
        """Remove emojis and special characters that might cause encoding issues"""
        return ''.join(char for char in message if ord(char) < 65536)
    
    def _log_to_database(self, level: str, message: str, details: str = "",
                        module: str = "", function: str = "", line_number: int = 0) -> None:
        """Log entry to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO activity_log (level, message, details, module, function, line_number)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (level, message, details, module, function, line_number))
            
            conn.commit()
            conn.close()
        except Exception as e:
            # Fallback to file logging if database fails
            self.logger.error(f"Failed to log to database: {str(e)}")
    
    def get_recent_logs(self, limit: int = 100, level_filter: str = None) -> List[Dict]:
        """
        Get recent log entries
        
        Args:
            limit: Maximum number of logs to return
            level_filter: Filter by log level (optional)
            
        Returns:
            List of log entries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if level_filter:
                cursor.execute('''
                    SELECT timestamp, level, message, details, module, function
                    FROM activity_log 
                    WHERE level = ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (level_filter, limit))
            else:
                cursor.execute('''
                    SELECT timestamp, level, message, details, module, function
                    FROM activity_log 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            
            logs = []
            for row in cursor.fetchall():
                logs.append({
                    'timestamp': row[0],
                    'level': row[1],
                    'message': row[2],
                    'details': row[3],
                    'module': row[4],
                    'function': row[5]
                })
            
            conn.close()
            return logs
        except Exception as e:
            self.logger.error(f"Failed to retrieve logs: {str(e)}")
            return []
    
    def get_log_statistics(self, hours: int = 24) -> Dict[str, int]:
        """
        Get log statistics for the specified time period
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with log level counts
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            cursor.execute('''
                SELECT level, COUNT(*) as count
                FROM activity_log 
                WHERE datetime(timestamp) > datetime(?)
                GROUP BY level
            ''', (cutoff_time.isoformat(),))
            
            stats = {}
            for row in cursor.fetchall():
                stats[row[0]] = row[1]
            
            conn.close()
            return stats
        except Exception as e:
            self.logger.error(f"Failed to get log statistics: {str(e)}")
            return {}
    
    def cleanup_old_logs(self, days: int = 30) -> int:
        """
        Clean up old log entries
        
        Args:
            days: Number of days to keep logs
            
        Returns:
            Number of deleted entries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_time = datetime.now() - timedelta(days=days)
            
            cursor.execute('''
                DELETE FROM activity_log 
                WHERE timestamp < ?
            ''', (cutoff_time.isoformat(),))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            self.log("INFO", f"Cleaned up {deleted_count} old log entries")
            return deleted_count
        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {str(e)}")
            return 0
    
    def export_logs(self, output_file: str, start_date: str = None, 
                   end_date: str = None, level_filter: str = None) -> bool:
        """
        Export logs to file
        
        Args:
            output_file: Output file path
            start_date: Start date filter (YYYY-MM-DD)
            end_date: End date filter (YYYY-MM-DD)
            level_filter: Level filter
            
        Returns:
            True if export successful
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build query with filters
            query = "SELECT * FROM activity_log WHERE 1=1"
            params = []
            
            if start_date:
                query += " AND date(timestamp) >= ?"
                params.append(start_date)
            
            if end_date:
                query += " AND date(timestamp) <= ?"
                params.append(end_date)
            
            if level_filter:
                query += " AND level = ?"
                params.append(level_filter)
            
            query += " ORDER BY timestamp DESC"
            
            cursor.execute(query, params)
            
            # Export to JSON
            logs = []
            for row in cursor.fetchall():
                logs.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'level': row[2],
                    'message': row[3],
                    'details': row[4],
                    'module': row[5],
                    'function': row[6],
                    'line_number': row[7]
                })
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
            
            conn.close()
            self.log("INFO", f"Exported {len(logs)} log entries to {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to export logs: {str(e)}")
            return False


# Convenience functions for backward compatibility
_log_manager = None

def get_log_manager(db_path: str = "agent_data.db", log_file: str = "agent.log") -> LogManager:
    """Get or create the global log manager instance"""
    global _log_manager
    if _log_manager is None:
        _log_manager = LogManager(db_path, log_file)
    return _log_manager

def log_info(message: str, details: str = "", module: str = "", function: str = ""):
    """Log info message"""
    get_log_manager().log("INFO", message, details, module, function)

def log_error(message: str, details: str = "", module: str = "", function: str = ""):
    """Log error message"""
    get_log_manager().log("ERROR", message, details, module, function)

def log_warning(message: str, details: str = "", module: str = "", function: str = ""):
    """Log warning message"""
    get_log_manager().log("WARNING", message, details, module, function)

def log_success(message: str, details: str = "", module: str = "", function: str = ""):
    """Log success message"""
    get_log_manager().log("SUCCESS", message, details, module, function)
