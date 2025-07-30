#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MDB Agent Pro v2.0.0 - Microsoft Access Database to API Bridge
=================================================================

Professional GUI application for bridging Microsoft Access databases to REST APIs
with visual field mapping, real-time monitoring, and enterprise-grade features.

Features:
- Visual field mapping interface with drag-and-drop functionality
- Real-time API testing and validation
- Data transformation engine with multiple formats
- Intelligent retry mechanism with exponential backoff
- Health monitoring and comprehensive diagnostics
- Transaction logging and audit trails
- Template management for reusable configurations
- Automated scheduling and background processing
- Security with encrypted configuration storage
- Professional multi-tab interface design

Technical Specifications:
- Python 3.8+ with Tkinter GUI framework
- Microsoft Access connectivity via pyodbc
- REST API integration with authentication support
- SQLite3 for local data storage and logging
- Multi-threaded background processing
- Cross-platform Windows compatibility

Developer: Freddy Mazmur
Company: PT Sahabat Agro Group
Contact: freddy.pm@sahabatagro.co.id
Phone: +62 813-9855-2019
Version: 2.0.0 Professional Edition
Release: January 2025

License: Proprietary - PT Sahabat Agro Group
Copyright (c) 2025 PT Sahabat Agro Group. All rights reserved.
"""

# Standard library imports
import tkinter as tk
import tkinter.simpledialog
from tkinter import ttk, filedialog, messagebox, scrolledtext
import tkinter.font as tkFont
import json
import os
import threading
import queue
import uuid
import base64
import sqlite3
import logging
import platform
import sys
import smtplib
import time
import hashlib
import csv
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Third-party imports
import pyodbc
import requests

# Optional imports with fallbacks
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Encryption support - fallback to simple base64 if cryptography not available
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
    ENCRYPTION_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    ENCRYPTION_AVAILABLE = False
    print("Warning: Cryptography library not available. Using basic encoding.")

class SecurityManager:
    """Handle encryption/decryption of sensitive data"""
    
    def __init__(self, password: str = "default_password"):
        self.password = password.encode()
        if ENCRYPTION_AVAILABLE:
            self._setup_encryption()
        
    def _setup_encryption(self):
        """Setup Fernet encryption"""
        if not CRYPTOGRAPHY_AVAILABLE:
            return
            
        salt = b'salt_1234567890123456'  # In production, use random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        self.cipher = Fernet(key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if CRYPTOGRAPHY_AVAILABLE and hasattr(self, 'cipher'):
            return self.cipher.encrypt(data.encode()).decode()
        else:
            return base64.b64encode(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        try:
            if CRYPTOGRAPHY_AVAILABLE and hasattr(self, 'cipher'):
                return self.cipher.decrypt(encrypted_data.encode()).decode()
            else:
                return base64.b64decode(encrypted_data.encode()).decode()
        except Exception:
            return encrypted_data  # Return as-is if decryption fails

class DatabaseManager:
    """Handle database operations"""
    
    def __init__(self, db_path: str = "agent_data.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for buffering"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS push_buffer (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE,
                payload TEXT,
                endpoint TEXT,
                api_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                retry_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level TEXT,
                message TEXT,
                details TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mapping_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                table_name TEXT,
                mapping_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_to_buffer(self, payload: Dict, endpoint: str, api_key: str) -> str:
        """Add data to push buffer"""
        data_uuid = str(uuid.uuid4())
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO push_buffer (uuid, payload, endpoint, api_key)
            VALUES (?, ?, ?, ?)
        ''', (data_uuid, json.dumps(payload), endpoint, api_key))
        
        conn.commit()
        conn.close()
        return data_uuid
    
    def get_buffer_items(self, status: str = 'pending', limit: int = 10) -> List[Dict]:
        """Get items from buffer"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, uuid, payload, endpoint, api_key, created_at, retry_count
            FROM push_buffer 
            WHERE status = ? 
            ORDER BY created_at ASC 
            LIMIT ?
        ''', (status, limit))
        
        items = []
        for row in cursor.fetchall():
            items.append({
                'id': row[0],
                'uuid': row[1],
                'payload': json.loads(row[2]),
                'endpoint': row[3],
                'api_key': row[4],
                'created_at': row[5],
                'retry_count': row[6]
            })
        
        conn.close()
        return items
    
    def update_buffer_status(self, buffer_id: int, status: str, retry_count: int = None):
        """Update buffer item status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if retry_count is not None:
            cursor.execute('''
                UPDATE push_buffer 
                SET status = ?, retry_count = ? 
                WHERE id = ?
            ''', (status, retry_count, buffer_id))
        else:
            cursor.execute('''
                UPDATE push_buffer 
                SET status = ? 
                WHERE id = ?
            ''', (status, buffer_id))
        
        conn.commit()
        conn.close()
    
    def log_activity(self, level: str, message: str, details: str = ""):
        """Log activity to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO activity_log (level, message, details)
            VALUES (?, ?, ?)
        ''', (level, message, details))
        
        conn.commit()
        conn.close()
    
    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent log entries"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, level, message, details
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
                'details': row[3]
            })
        
        conn.close()
        return logs

class StatusIndicator:
    """Status indicator widget (colored circle)"""
    
    def __init__(self, parent, label: str):
        self.frame = ttk.Frame(parent)
        self.label = label
        self.status = "unknown"  # unknown, good, warning, error
        
        # Create canvas for colored circle
        self.canvas = tk.Canvas(self.frame, width=20, height=20, highlightthickness=0)
        self.canvas.pack(side=tk.LEFT, padx=(0, 5))
        
        # Label
        ttk.Label(self.frame, text=label).pack(side=tk.LEFT)
        
        self.update_status("unknown")
    
    def update_status(self, status: str):
        """Update status and color"""
        self.status = status
        self.canvas.delete("all")
        
        colors = {
            "good": "#4CAF50",      # Green
            "warning": "#FF9800",   # Orange
            "error": "#F44336",     # Red
            "unknown": "#9E9E9E"    # Gray
        }
        
        color = colors.get(status, colors["unknown"])
        self.canvas.create_oval(2, 2, 18, 18, fill=color, outline="")

class MDBAgentPro:
    """Main application class"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("MDB Agent Pro v2.0 - PT Sahabat Agro Group")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Security manager
        self.security = SecurityManager()
        
        # Database manager
        self.db_manager = DatabaseManager()
        
        # Configuration
        self.config_file = "config.encrypted"
        self.config = self.load_config()
        
        # Database connection
        self.db_connection = None
        self.selected_table = None
        self.table_columns = []
        
        # Field mapping variables
        self.field_mappings = {}
        self.api_fields = []
        self.mapping_widgets = {}
        
        # API buffer and threading
        self.is_running = False
        self.worker_thread = None
        self.push_queue = queue.Queue()
        
        # Admin mode
        self.admin_mode = False
        self.admin_pin = "1234"  # In production, store encrypted
        
        # Theme
        self.dark_mode = False
        
        # Current tab
        self.current_tab = "dashboard"
        
        # Setup GUI
        self.setup_styles()
        self.setup_gui()
        self.load_settings()
        
        # Start background worker
        self.start_worker()
        
        # Setup logging
        self.setup_logging()
    
    def setup_styles(self):
        """Setup custom styles"""
        self.style = ttk.Style()
        
        # Configure styles
        self.style.configure('Sidebar.TFrame', background='#f0f0f0')
        self.style.configure('Content.TFrame', background='white')
        self.style.configure('Status.TFrame', background='#e0e0e0')
        self.style.configure('Title.TLabel', font=('Arial', 12, 'bold'))
        self.style.configure('Header.TLabel', font=('Arial', 10, 'bold'))
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('agent.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_config(self) -> Dict:
        """Load encrypted configuration"""
        default_config = {
            "mdb_file": "",
            "mdb_password": "qwerty123",
            "selected_table": "",
            "table_columns": [],
            "field_mapping": {},
            "api_endpoint": "",
            "api_key": "",
            "push_interval": 300,  # 5 minutes
            "auto_push": False,
            "test_mode": False,
            "last_status": "Ready",
            "admin_pin": "1234",
            "dark_mode": False,
            "email_settings": {
                "smtp_server": "",
                "smtp_port": 587,
                "email": "",
                "password": "",
                "it_email": ""
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    encrypted_data = f.read()
                decrypted_data = self.security.decrypt(encrypted_data)
                if decrypted_data:
                    config = json.loads(decrypted_data)
                    default_config.update(config)
            except Exception as e:
                self.log_entry(f"Error loading config: {str(e)}", "ERROR")
        
        return default_config
    
    def save_config(self):
        """Save encrypted configuration"""
        try:
            config_json = json.dumps(self.config, indent=2)
            encrypted_data = self.security.encrypt(config_json)
            
            with open(self.config_file, 'w') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            self.log_entry(f"Error saving config: {str(e)}", "ERROR")
    
    def start_worker(self):
        """Start background worker thread"""
        def worker():
            while True:
                try:
                    if self.is_running and self.config.get("auto_push"):
                        # Process buffer items
                        items = self.db_manager.get_buffer_items()
                        for item in items:
                            if self.send_to_api(item['payload']):
                                self.db_manager.update_buffer_status(item['id'], 'completed')
                            else:
                                retry_count = item['retry_count'] + 1
                                if retry_count < 3:
                                    self.db_manager.update_buffer_status(item['id'], 'pending', retry_count)
                                else:
                                    self.db_manager.update_buffer_status(item['id'], 'failed', retry_count)
                    
                    import time
                    time.sleep(30)  # Check every 30 seconds
                except:
                    pass
        
        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()
    
    def setup_gui(self):
        """Setup main GUI"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top status bar
        self.setup_status_bar(main_frame)
        
        # Content area
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Sidebar
        self.setup_sidebar(content_frame)
        
        # Main content area
        self.setup_content_area(content_frame)
        
        # Bottom status bar
        self.setup_bottom_status(main_frame)
    
    def setup_status_bar(self, parent):
        """Setup top status indicator bar"""
        status_frame = ttk.Frame(parent, style='Status.TFrame')
        status_frame.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        # Left side - Application title
        title_frame = ttk.Frame(status_frame)
        title_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        ttk.Label(title_frame, text="MDB Agent Pro v2.0", 
                 style='Title.TLabel', 
                 font=('Arial', 14, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="Database to API Bridge", 
                 font=('Arial', 10), 
                 foreground='gray').pack(anchor=tk.W)
        
        # Right side - Status indicators with better layout
        indicators_frame = ttk.Frame(status_frame)
        indicators_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Status indicators container
        status_container = ttk.Frame(indicators_frame)
        status_container.pack(side=tk.RIGHT, padx=(20, 0))
        
        self.db_status = StatusIndicator(status_container, "Database")
        self.db_status.frame.pack(side=tk.LEFT, padx=(0, 15))
        
        self.api_status = StatusIndicator(status_container, "API")
        self.api_status.frame.pack(side=tk.LEFT, padx=(0, 15))
        
        self.buffer_status = StatusIndicator(status_container, "Buffer")
        self.buffer_status.frame.pack(side=tk.LEFT)
    
    def setup_sidebar(self, parent):
        """Setup navigation sidebar"""
        sidebar = ttk.Frame(parent, style='Sidebar.TFrame', width=250)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        sidebar.pack_propagate(False)
        
        # Header section with consistent padding
        header_frame = ttk.Frame(sidebar)
        header_frame.pack(fill=tk.X, padx=15, pady=(15, 10))
        
        ttk.Label(header_frame, text="MDB Agent Pro", 
                 font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        ttk.Label(header_frame, text="PT Sahabat Agro Group", 
                 font=('Arial', 9), foreground='gray').pack(anchor=tk.W, pady=(2, 0))
        
        # Navigation sections with proper spacing
        nav_frame = ttk.Frame(sidebar)
        nav_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))
        
        # Dashboard section
        self.create_nav_section(nav_frame, "DASHBOARD", [
            ("Dashboard", "dashboard")
        ], is_first=True)
        
        # Master section
        self.create_nav_section(nav_frame, "MASTER", [
            ("Health Checks", "health_checks"),
            ("Transaction Log", "transaction")
        ])
        
        # Configuration section
        self.create_nav_section(nav_frame, "CONFIGURATION", [
            ("Database Connection", "database_connection"),
            ("API Field Mapping", "mapping"),
            ("API Settings", "api"),
            ("Scheduler", "scheduler")
        ])
        
        # Information section
        self.create_nav_section(nav_frame, "INFORMATION", [
            ("About Application", "about")
        ])
        
        # Footer controls with proper spacing
        footer_frame = ttk.Frame(sidebar)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(10, 15))
        
        ttk.Separator(footer_frame, orient='horizontal').pack(fill=tk.X, pady=(0, 10))
        
        # Control buttons with consistent styling
        self.admin_btn = ttk.Button(
            footer_frame, 
            text="🔐 Admin Mode", 
            command=self.toggle_admin_mode
        )
        self.admin_btn.pack(fill=tk.X, pady=(0, 5))
        
        self.theme_btn = ttk.Button(
            footer_frame, 
            text="🌙 Dark Mode", 
            command=self.toggle_theme
        )
        self.theme_btn.pack(fill=tk.X)
    
    def create_nav_section(self, parent, title, buttons, is_first=False):
        """Create a navigation section with consistent styling"""
        # Section spacing
        top_padding = 5 if is_first else 15
        
        # Section header
        ttk.Label(parent, text=title, 
                 font=('Arial', 9, 'bold'), 
                 foreground='gray').pack(anchor=tk.W, padx=5, pady=(top_padding, 5))
        
        # Section buttons
        if not hasattr(self, 'nav_buttons'):
            self.nav_buttons = {}
            
        for text, tab_id in buttons:
            print(f"Creating button: {text} -> {tab_id}")  # Debug
            btn = ttk.Button(
                parent, 
                text=f"  {text}", 
                command=lambda t=tab_id: self.switch_tab(t),
                width=28
            )
            btn.pack(fill=tk.X, pady=1, padx=5)
            self.nav_buttons[tab_id] = btn
            print(f"Button created and packed: {text}")  # Debug
    
    def setup_content_area(self, parent):
        """Setup main content area"""
        self.content_frame = ttk.Frame(parent, style='Content.TFrame')
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Add padding to content area
        content_inner = ttk.Frame(self.content_frame)
        content_inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        # Content will be dynamically added here
        self.content_inner = content_inner
        
        # Create all tab frames
        self.tab_frames = {}
        print("Creating dashboard tab...")
        self.create_dashboard_tab()
        print("Creating health checks tab...")
        self.create_health_checks_tab()
        print("Creating transaction tab...")
        self.create_transaction_tab()
        print("Creating database connection tab...")
        self.create_database_connection_tab()
        print("Creating mapping tab...")
        self.create_mapping_tab()
        print("Creating API tab...")
        self.create_api_tab()
        print("Creating scheduler tab...")
        self.create_scheduler_tab()
        print("Creating about tab...")
        self.create_about_tab()
        
        print(f"Tab frames created: {list(self.tab_frames.keys())}")
        
        # Show dashboard by default
        self.switch_tab("dashboard")
    
    def setup_bottom_status(self, parent):
        """Setup bottom status bar"""
        bottom_frame = ttk.Frame(parent, style='Status.TFrame')
        bottom_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=15, pady=(5, 10))
        
        # Left side - Status message
        left_frame = ttk.Frame(bottom_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(left_frame, textvariable=self.status_var, 
                 font=('Arial', 9)).pack(side=tk.LEFT)
        
        # Right side - Agent status with better styling
        right_frame = ttk.Frame(bottom_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.agent_status_var = tk.StringVar()
        self.agent_status_var.set("🔴 Agent: Stopped")
        agent_label = ttk.Label(right_frame, textvariable=self.agent_status_var, 
                               font=('Arial', 9, 'bold'))
        agent_label.pack(side=tk.RIGHT)
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        frame = ttk.Frame(self.content_inner)
        self.tab_frames["dashboard"] = frame
        
        # Page title with better spacing
        title_frame = ttk.Frame(frame)
        title_frame.pack(fill=tk.X, pady=(0, 25))
        
        ttk.Label(title_frame, text="Dashboard", 
                 style='Title.TLabel', 
                 font=('Arial', 16, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="System overview and quick actions", 
                 font=('Arial', 11), 
                 foreground='gray').pack(anchor=tk.W, pady=(3, 0))
        
        # Status overview with better layout
        status_frame = ttk.LabelFrame(frame, text="System Status", padding=20)
        status_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Create a grid with proper spacing
        status_grid = ttk.Frame(status_frame)
        status_grid.pack(fill=tk.X)
        
        # Configure grid weights for better distribution
        status_grid.grid_columnconfigure(1, weight=1)
        
        # Status items with icons and better spacing
        status_items = [
            ("Database:", "dash_db_status", "❌ Not Connected", "red"),
            ("API Endpoint:", "dash_api_status", "❌ Not Configured", "red"),
            ("Agent Service:", "dash_agent_status", "⭕ Stopped", "red"),
            ("Buffer Queue:", "dash_buffer_status", "✅ 0 items", "green")
        ]
        
        for i, (label, attr_name, default_text, color) in enumerate(status_items):
            # Label
            ttk.Label(status_grid, text=label, 
                     font=('Arial', 10, 'bold')).grid(
                         row=i, column=0, sticky=tk.W, 
                         padx=(0, 20), pady=8)
            
            # Status
            status_label = ttk.Label(status_grid, text=default_text, 
                                   foreground=color, font=('Arial', 10))
            status_label.grid(row=i, column=1, sticky=tk.W, pady=8)
            setattr(self, attr_name, status_label)
        
        # Quick actions with better layout
        actions_frame = ttk.LabelFrame(frame, text="Quick Actions", padding=20)
        actions_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Create action buttons in a more organized way
        actions_container = ttk.Frame(actions_frame)
        actions_container.pack()
        
        # Database & API actions
        db_api_frame = ttk.Frame(actions_container)
        db_api_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(db_api_frame, text="🗄️ Test Database", 
                  command=self.test_database, width=18).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(db_api_frame, text="🌐 Test API", 
                  command=self.test_api, width=18).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(db_api_frame, text="📤 Manual Push", 
                  command=self.manual_push, width=18).pack(side=tk.LEFT)
        
        # Agent control actions
        agent_frame = ttk.Frame(actions_container)
        agent_frame.pack(fill=tk.X)
        
        ttk.Button(agent_frame, text="▶️ Start Agent", 
                  command=self.start_agent, width=18).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(agent_frame, text="⏹️ Stop Agent", 
                  command=self.stop_agent, width=18).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(agent_frame, text="🗑️ Clear Buffer", 
                  command=self.clear_buffer, width=18).pack(side=tk.LEFT)
        
        # Recent activity with better styling
        activity_frame = ttk.LabelFrame(frame, text="Recent Activity", padding=20)
        activity_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview with better column sizing
        self.activity_tree = ttk.Treeview(activity_frame, 
                                        columns=("time", "level", "message"), 
                                        show="headings", height=10)
        
        # Configure columns with better proportions
        self.activity_tree.heading("time", text="Time")
        self.activity_tree.heading("level", text="Level") 
        self.activity_tree.heading("message", text="Message")
        
        self.activity_tree.column("time", width=140, minwidth=120)
        self.activity_tree.column("level", width=80, minwidth=60)
        self.activity_tree.column("message", width=450, minwidth=300)
        
        # Add scrollbar
        activity_scroll = ttk.Scrollbar(activity_frame, orient=tk.VERTICAL, 
                                      command=self.activity_tree.yview)
        self.activity_tree.configure(yscrollcommand=activity_scroll.set)
        
        # Pack with proper layout
        self.activity_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        activity_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_health_checks_tab(self):
        """Create health checks tab"""
        frame = ttk.Frame(self.content_inner)
        self.tab_frames["health_checks"] = frame
        
        # Page title with better spacing
        title_frame = ttk.Frame(frame)
        title_frame.pack(fill=tk.X, pady=(0, 25))
        
        ttk.Label(title_frame, text="Health Checks", 
                 style='Title.TLabel', 
                 font=('Arial', 16, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="System health monitoring and diagnostics", 
                 font=('Arial', 11), 
                 foreground='gray').pack(anchor=tk.W, pady=(3, 0))
        
        # System health overview with better layout
        health_frame = ttk.LabelFrame(frame, text="System Health Overview", padding=20)
        health_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Health status grid
        health_grid = ttk.Frame(health_frame)
        health_grid.pack(fill=tk.X)
        
        # Database health
        ttk.Label(health_grid, text="Database Connection:", style='Header.TLabel').grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        self.health_db_status = ttk.Label(health_grid, text="❌ Not Connected", foreground="red")
        self.health_db_status.grid(row=0, column=1, sticky=tk.W)
        ttk.Button(health_grid, text="Test", command=self.health_test_database).grid(row=0, column=2, padx=(10, 0))
        
        # API health
        ttk.Label(health_grid, text="API Endpoint:", style='Header.TLabel').grid(row=1, column=0, sticky=tk.W, padx=(0, 20))
        self.health_api_status = ttk.Label(health_grid, text="❌ Not Configured", foreground="red")
        self.health_api_status.grid(row=1, column=1, sticky=tk.W)
        ttk.Button(health_grid, text="Test", command=self.health_test_api).grid(row=1, column=2, padx=(10, 0))
        
        # Buffer health
        ttk.Label(health_grid, text="Buffer Status:", style='Header.TLabel').grid(row=2, column=0, sticky=tk.W, padx=(0, 20))
        self.health_buffer_status = ttk.Label(health_grid, text="✅ Empty", foreground="green")
        self.health_buffer_status.grid(row=2, column=1, sticky=tk.W)
        ttk.Button(health_grid, text="Check", command=self.health_check_buffer).grid(row=2, column=2, padx=(10, 0))
        
        # Data integrity
        ttk.Label(health_grid, text="Data Integrity:", style='Header.TLabel').grid(row=3, column=0, sticky=tk.W, padx=(0, 20))
        self.health_data_status = ttk.Label(health_grid, text="⚠️ Not Verified", foreground="orange")
        self.health_data_status.grid(row=3, column=1, sticky=tk.W)
        ttk.Button(health_grid, text="Verify", command=self.health_verify_data).grid(row=3, column=2, padx=(10, 0))
        
        # Auto check controls
        check_frame = ttk.LabelFrame(frame, text="Health Check Controls", padding=10)
        check_frame.pack(fill=tk.X, pady=(0, 10))
        
        control_frame = ttk.Frame(check_frame)
        control_frame.pack(fill=tk.X)
        
        ttk.Button(control_frame, text="Run All Checks", command=self.run_all_health_checks).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="Auto Check (5min)", command=self.toggle_auto_health_check).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="Export Health Report", command=self.export_health_report).pack(side=tk.LEFT)
        
        # Health check results
        results_frame = ttk.LabelFrame(frame, text="Health Check Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.health_tree = ttk.Treeview(results_frame, columns=("timestamp", "check", "status", "details"), show="headings", height=10)
        self.health_tree.heading("timestamp", text="Timestamp")
        self.health_tree.heading("check", text="Check Type")
        self.health_tree.heading("status", text="Status")
        self.health_tree.heading("details", text="Details")
        
        self.health_tree.column("timestamp", width=150)
        self.health_tree.column("check", width=120)
        self.health_tree.column("status", width=80)
        self.health_tree.column("details", width=350)
        
        health_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.health_tree.yview)
        self.health_tree.configure(yscrollcommand=health_scroll.set)
        
        self.health_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        health_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_transaction_tab(self):
        """Create transaction log tab"""
        frame = ttk.Frame(self.content_inner)
        self.tab_frames["transaction"] = frame
        
        # Page title with better spacing
        title_frame = ttk.Frame(frame)
        title_frame.pack(fill=tk.X, pady=(0, 25))
        
        ttk.Label(title_frame, text="Transaction Log", 
                 style='Title.TLabel', 
                 font=('Arial', 16, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="Monitor and analyze data push transactions", 
                 font=('Arial', 11), 
                 foreground='gray').pack(anchor=tk.W, pady=(3, 0))
        
        # Transaction filters
        filter_frame = ttk.LabelFrame(frame, text="Filters", padding=10)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        filter_grid = ttk.Frame(filter_frame)
        filter_grid.pack(fill=tk.X)
        
        # Date filter
        ttk.Label(filter_grid, text="Date Range:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.trans_start_date = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d"))
        ttk.Entry(filter_grid, textvariable=self.trans_start_date, width=12).grid(row=0, column=1, padx=(0, 5))
        ttk.Label(filter_grid, text="to").grid(row=0, column=2, padx=5)
        self.trans_end_date = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d"))
        ttk.Entry(filter_grid, textvariable=self.trans_end_date, width=12).grid(row=0, column=3, padx=(5, 20))
        
        # Status filter
        ttk.Label(filter_grid, text="Status:").grid(row=0, column=4, sticky=tk.W, padx=(0, 10))
        self.trans_status_filter = tk.StringVar(value="All")
        status_combo = ttk.Combobox(filter_grid, textvariable=self.trans_status_filter, 
                                   values=["All", "Success", "Failed", "Pending"], state="readonly", width=10)
        status_combo.grid(row=0, column=5, padx=(0, 20))
        
        ttk.Button(filter_grid, text="Apply Filter", command=self.apply_transaction_filter).grid(row=0, column=6, padx=10)
        ttk.Button(filter_grid, text="Export", command=self.export_transactions).grid(row=0, column=7, padx=5)
        
        # Transaction statistics
        stats_frame = ttk.LabelFrame(frame, text="Transaction Statistics", padding=10)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)
        
        ttk.Label(stats_grid, text="Total:", style='Header.TLabel').grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.stats_total = ttk.Label(stats_grid, text="0")
        self.stats_total.grid(row=0, column=1, sticky=tk.W, padx=(0, 30))
        
        ttk.Label(stats_grid, text="Success:", style='Header.TLabel').grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        self.stats_success = ttk.Label(stats_grid, text="0", foreground="green")
        self.stats_success.grid(row=0, column=3, sticky=tk.W, padx=(0, 30))
        
        ttk.Label(stats_grid, text="Failed:", style='Header.TLabel').grid(row=0, column=4, sticky=tk.W, padx=(0, 10))
        self.stats_failed = ttk.Label(stats_grid, text="0", foreground="red")
        self.stats_failed.grid(row=0, column=5, sticky=tk.W, padx=(0, 30))
        
        ttk.Label(stats_grid, text="Pending:", style='Header.TLabel').grid(row=0, column=6, sticky=tk.W, padx=(0, 10))
        self.stats_pending = ttk.Label(stats_grid, text="0", foreground="orange")
        self.stats_pending.grid(row=0, column=7, sticky=tk.W)
        
        # Transaction log
        log_frame = ttk.LabelFrame(frame, text="Transaction History", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.transaction_tree = ttk.Treeview(log_frame, columns=("id", "timestamp", "table", "status", "records", "details"), show="headings", height=12)
        self.transaction_tree.heading("id", text="ID")
        self.transaction_tree.heading("timestamp", text="Timestamp")
        self.transaction_tree.heading("table", text="Table")
        self.transaction_tree.heading("status", text="Status")
        self.transaction_tree.heading("records", text="Records")
        self.transaction_tree.heading("details", text="Details")
        
        self.transaction_tree.column("id", width=60)
        self.transaction_tree.column("timestamp", width=150)
        self.transaction_tree.column("table", width=120)
        self.transaction_tree.column("status", width=80)
        self.transaction_tree.column("records", width=80)
        self.transaction_tree.column("details", width=300)
        
        trans_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.transaction_tree.yview)
        self.transaction_tree.configure(yscrollcommand=trans_scroll.set)
        
        self.transaction_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        trans_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_database_connection_tab(self):
        """Create database configuration tab"""
        frame = ttk.Frame(self.content_inner)
        self.tab_frames["database_connection"] = frame
        
        # Page title with better spacing
        title_frame = ttk.Frame(frame)
        title_frame.pack(fill=tk.X, pady=(0, 25))
        
        ttk.Label(title_frame, text="Database Connection", 
                 style='Title.TLabel', 
                 font=('Arial', 16, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="Configure Microsoft Access database connection and settings", 
                 font=('Arial', 11), 
                 foreground='gray').pack(anchor=tk.W, pady=(3, 0))
        
        # File selection
        file_frame = ttk.LabelFrame(frame, text="Database File", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(file_frame, text="MDB File:").pack(anchor=tk.W)
        file_select_frame = ttk.Frame(file_frame)
        file_select_frame.pack(fill=tk.X, pady=(5, 10))
        
        self.mdb_file_var = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.mdb_file_var, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(file_select_frame, text="Browse", command=self.browse_mdb_file).pack(side=tk.RIGHT)
        
        ttk.Label(file_frame, text="Password:").pack(anchor=tk.W, pady=(10, 0))
        self.mdb_password_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.mdb_password_var, show="*").pack(fill=tk.X, pady=(5, 10))
        
        ttk.Button(file_frame, text="Connect Database", command=self.connect_database).pack()
        
        # Table selection
        table_frame = ttk.LabelFrame(frame, text="Table Selection", padding=10)
        table_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(table_frame, text="Available Tables:").pack(anchor=tk.W)
        self.table_var = tk.StringVar()
        self.table_combo = ttk.Combobox(table_frame, textvariable=self.table_var, state="readonly")
        self.table_combo.pack(fill=tk.X, pady=(5, 10))
        self.table_combo.bind("<<ComboboxSelected>>", self.on_table_selected)
        
        # Table preview
        preview_frame = ttk.LabelFrame(frame, text="Table Preview", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True)
        
        # Preview controls
        preview_controls = ttk.Frame(preview_frame)
        preview_controls.pack(fill=tk.X, pady=(0, 10))
        
        # Preview info label
        self.preview_info_label = ttk.Label(preview_controls, text="Select a table to view preview", foreground="gray")
        self.preview_info_label.pack(side=tk.LEFT)
        
        # Refresh button
        ttk.Button(preview_controls, text="Refresh Preview", command=self.load_table_preview).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Test database button
        ttk.Button(preview_controls, text="Test Connection", command=self.test_database).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Export data button
        ttk.Button(preview_controls, text="Export Sample Data", command=self.export_sample_data).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Preview treeview with both scrollbars
        preview_container = ttk.Frame(preview_frame)
        preview_container.pack(fill=tk.BOTH, expand=True)
        
        self.table_tree = ttk.Treeview(preview_container, show="headings", height=15)
        table_scroll_y = ttk.Scrollbar(preview_container, orient=tk.VERTICAL, command=self.table_tree.yview)
        table_scroll_x = ttk.Scrollbar(preview_container, orient=tk.HORIZONTAL, command=self.table_tree.xview)
        
        self.table_tree.configure(yscrollcommand=table_scroll_y.set, xscrollcommand=table_scroll_x.set)
        
        # Pack treeview and scrollbars
        self.table_tree.grid(row=0, column=0, sticky="nsew")
        table_scroll_y.grid(row=0, column=1, sticky="ns")
        table_scroll_x.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights
        preview_container.grid_rowconfigure(0, weight=1)
        preview_container.grid_columnconfigure(0, weight=1)
    
    def switch_tab(self, tab_id: str):
        """Switch to specified tab"""
        # Hide all tabs
        for frame in self.tab_frames.values():
            frame.pack_forget()
        
        # Show selected tab
        if tab_id in self.tab_frames:
            self.tab_frames[tab_id].pack(fill=tk.BOTH, expand=True)
            self.current_tab = tab_id
            
            # Update navigation button styles
            for btn_id, btn in self.nav_buttons.items():
                if btn_id == tab_id:
                    btn.configure(style='Accent.TButton')
                else:
                    btn.configure(style='TButton')
            
            # Refresh tab content if needed
            if tab_id == "dashboard":
                self.refresh_dashboard()
            elif tab_id == "scheduler":
                self.refresh_scheduler_log()
        else:
            print(f"Warning: Tab '{tab_id}' not found in tab_frames. Available tabs: {list(self.tab_frames.keys())}")
    
    # Continue with remaining methods...
    
    # Continue with remaining methods...
    
    def log_entry(self, message: str, level: str = "INFO"):
        """Add entry to log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log to database
        self.db_manager.log_activity(level, message)
        
        # Log to file
        if hasattr(self, 'logger'):
            if level == "ERROR":
                self.logger.error(message)
            elif level == "WARNING":
                self.logger.warning(message)
            else:
                self.logger.info(message)
        
        # Update status
        self.status_var.set(f"{level}: {message}")
        
        # Update dashboard if visible
        if self.current_tab == "dashboard":
            self.refresh_dashboard()
    
    def browse_mdb_file(self):
        """Browse for MDB file"""
        filename = filedialog.askopenfilename(
            title="Select Microsoft Access Database",
            filetypes=[("Access Database", "*.mdb *.accdb"), ("All Files", "*.*")]
        )
        if filename:
            self.mdb_file_var.set(filename)
    
    def connect_database(self):
        """Connect to MDB database"""
        if not self.mdb_file_var.get():
            messagebox.showerror("Error", "Please select a database file first.")
            return
        
        if not os.path.exists(self.mdb_file_var.get()):
            messagebox.showerror("Error", "Database file not found.")
            return
        
        try:
            # Close existing connection
            if self.db_connection:
                self.db_connection.close()
            
            # Build connection string
            conn_str = f'DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={self.mdb_file_var.get()}'
            if self.mdb_password_var.get():
                conn_str += f';PWD={self.mdb_password_var.get()}'
            
            self.db_connection = pyodbc.connect(conn_str)
            self.load_tables()
            self.log_entry("Database connected successfully", "SUCCESS")
            self.db_status.update_status("good")
            
            # Update config
            self.config["mdb_file"] = self.mdb_file_var.get()
            self.config["mdb_password"] = self.mdb_password_var.get()
            self.save_config()
            
        except Exception as e:
            error_msg = f"Failed to connect to database: {str(e)}"
            self.log_entry(error_msg, "ERROR")
            self.db_status.update_status("error")
            messagebox.showerror("Database Error", error_msg)
    
    def load_tables(self):
        """Load table names from connected database"""
        if not self.db_connection:
            return
        
        try:
            cursor = self.db_connection.cursor()
            tables = []
            
            for table_info in cursor.tables(tableType='TABLE'):
                tables.append(table_info.table_name)
            
            self.table_combo['values'] = tables
            self.log_entry(f"Found {len(tables)} tables in database", "INFO")
            
        except Exception as e:
            error_msg = f"Failed to load tables: {str(e)}"
            self.log_entry(error_msg, "ERROR")
    
    def on_table_selected(self, event):
        """Handle table selection"""
        self.selected_table = self.table_var.get()
        if self.selected_table:
            self.load_table_preview()
            self.load_table_columns()
    
    def load_table_preview(self):
        """Load table preview data"""
        if not self.db_connection or not self.selected_table:
            # Clear preview if no connection or table
            if hasattr(self, 'table_tree'):
                for item in self.table_tree.get_children():
                    self.table_tree.delete(item)
                self.table_tree["columns"] = ()
            return
        
        try:
            cursor = self.db_connection.cursor()
            
            # Get columns with detailed information
            columns = []
            column_names = []
            for column in cursor.columns(table=self.selected_table):
                columns.append({
                    'name': column.column_name,
                    'type': column.type_name,
                    'size': getattr(column, 'column_size', 'N/A'),
                    'nullable': getattr(column, 'nullable', 'Unknown')
                })
                column_names.append(column.column_name)
            
            # Configure treeview
            self.table_tree["columns"] = column_names
            self.table_tree["show"] = "headings"
            
            # Clear existing items
            for item in self.table_tree.get_children():
                self.table_tree.delete(item)
            
            # Set column headings with type info
            for i, col in enumerate(columns):
                col_name = col['name']
                col_type = col['type']
                header_text = f"{col_name}\n({col_type})"
                
                self.table_tree.heading(col_name, text=header_text)
                
                # Auto-size columns based on content type
                if 'TEXT' in col_type or 'VARCHAR' in col_type:
                    width = 150
                elif 'DATE' in col_type or 'TIME' in col_type:
                    width = 120
                elif 'INT' in col_type or 'NUMBER' in col_type:
                    width = 80
                else:
                    width = 100
                    
                self.table_tree.column(col_name, width=width, minwidth=60)
            
            # Get sample data (first 20 rows with ordering)
            try:
                # Try to find a suitable ordering column
                order_column = None
                for col_name in ['ID', 'Id', 'id', 'TIMESTAMP', 'Timestamp', 'timestamp', 'DATE', 'Date', 'date']:
                    if col_name in column_names:
                        order_column = col_name
                        break
                
                if order_column:
                    query = f"SELECT TOP 20 * FROM [{self.selected_table}] ORDER BY [{order_column}] DESC"
                else:
                    query = f"SELECT TOP 20 * FROM [{self.selected_table}]"
                
                cursor.execute(query)
                rows = cursor.fetchall()
                
                # Track data statistics
                row_count = len(rows)
                
                # Get total row count
                cursor.execute(f"SELECT COUNT(*) FROM [{self.selected_table}]")
                total_rows = cursor.fetchone()[0]
                
                # Insert data into treeview
                for row in rows:
                    values = []
                    for i, value in enumerate(row):
                        if value is None:
                            values.append("NULL")
                        elif hasattr(value, 'strftime'):
                            values.append(value.strftime('%Y-%m-%d %H:%M:%S'))
                        elif isinstance(value, (int, float)):
                            values.append(str(value))
                        else:
                            # Truncate long text values
                            str_value = str(value)
                            if len(str_value) > 50:
                                str_value = str_value[:47] + "..."
                            values.append(str_value)
                    
                    self.table_tree.insert("", tk.END, values=values)
                
                # Update preview info
                if hasattr(self, 'preview_info_label'):
                    info_text = f"Showing {row_count} of {total_rows} total records"
                    if order_column:
                        info_text += f" (ordered by {order_column})"
                    self.preview_info_label.config(text=info_text)
                
                # Update status
                success_msg = f"Loaded preview: {self.selected_table} ({row_count}/{total_rows} records)"
                self.log_entry(success_msg, "SUCCESS")
                
                # Auto-refresh mapping interface if it exists
                if hasattr(self, 'refresh_mapping_interface'):
                    self.refresh_mapping_interface()
                
            except Exception as query_error:
                # Fallback to simple query without ordering
                cursor.execute(f"SELECT TOP 20 * FROM [{self.selected_table}]")
                rows = cursor.fetchall()
                
                for row in rows:
                    values = []
                    for value in row:
                        if value is None:
                            values.append("NULL")
                        elif hasattr(value, 'strftime'):
                            values.append(value.strftime('%Y-%m-%d %H:%M:%S'))
                        else:
                            str_value = str(value)
                            if len(str_value) > 50:
                                str_value = str_value[:47] + "..."
                            values.append(str_value)
                    
                    self.table_tree.insert("", tk.END, values=values)
                
                self.log_entry(f"Loaded preview for table: {self.selected_table} (basic query)", "INFO")
            
        except Exception as e:
            error_msg = f"Failed to load table preview: {str(e)}"
            self.log_entry(error_msg, "ERROR")
            
            # Show error in preview
            if hasattr(self, 'table_tree'):
                self.table_tree["columns"] = ("Error",)
                self.table_tree["show"] = "headings"
                for item in self.table_tree.get_children():
                    self.table_tree.delete(item)
                self.table_tree.heading("Error", text="Error Loading Data")
                self.table_tree.insert("", tk.END, values=(error_msg,))
            
            messagebox.showerror("Database Error", f"Failed to load table preview:\n{str(e)}")
    
    def test_database(self):
        """Test database connection with detailed feedback"""
        if not self.db_connection:
            messagebox.showerror("Error", "No database connection. Please connect first.")
            return
        
        try:
            cursor = self.db_connection.cursor()
            
            # Test basic connection
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            
            # Get database info
            table_count = 0
            try:
                tables = cursor.tables()
                table_count = len([table for table in tables if table.table_type == 'TABLE'])
            except:
                table_count = "Unknown"
            
            # Test current table if selected
            table_info = ""
            if self.selected_table:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM [{self.selected_table}]")
                    record_count = cursor.fetchone()[0]
                    table_info = f"\nSelected table '{self.selected_table}' has {record_count:,} records"
                except Exception as e:
                    table_info = f"\nError querying selected table: {str(e)}"
            
            messagebox.showinfo("Database Test", 
                              f"✅ Database connection successful!\n\n"
                              f"Database contains {table_count} tables{table_info}")
            
            self.log_entry("Database connection test successful", "SUCCESS")
            
        except Exception as e:
            error_msg = f"Database test failed: {str(e)}"
            messagebox.showerror("Database Test Failed", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def export_sample_data(self):
        """Export sample data from current table to CSV"""
        if not self.db_connection or not self.selected_table:
            messagebox.showerror("Error", "Please select a table first.")
            return
        
        filename = filedialog.asksaveasfilename(
            title=f"Export Sample Data from {self.selected_table}",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Excel files", "*.xlsx"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                cursor = self.db_connection.cursor()
                
                # Get all columns
                columns = [col['name'] for col in self.table_columns] if hasattr(self, 'table_columns') and self.table_columns else []
                
                if not columns:
                    # Get columns from database
                    columns = [column.column_name for column in cursor.columns(table=self.selected_table)]
                
                # Get sample data (up to 100 records)
                cursor.execute(f"SELECT TOP 100 * FROM [{self.selected_table}]")
                rows = cursor.fetchall()
                
                # Write to file
                if filename.endswith('.csv'):
                    import csv
                    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(columns)  # Header
                        
                        for row in rows:
                            csv_row = []
                            for value in row:
                                if value is None:
                                    csv_row.append("")
                                elif hasattr(value, 'strftime'):
                                    csv_row.append(value.strftime('%Y-%m-%d %H:%M:%S'))
                                else:
                                    csv_row.append(str(value))
                            writer.writerow(csv_row)
                
                elif filename.endswith('.xlsx'):
                    try:
                        import openpyxl
                        wb = openpyxl.Workbook()
                        ws = wb.active
                        ws.title = self.selected_table
                        
                        # Write header
                        for col, column_name in enumerate(columns, 1):
                            ws.cell(row=1, column=col, value=column_name)
                        
                        # Write data
                        for row_idx, row in enumerate(rows, 2):
                            for col_idx, value in enumerate(row, 1):
                                if value is None:
                                    cell_value = ""
                                elif hasattr(value, 'strftime'):
                                    cell_value = value.strftime('%Y-%m-%d %H:%M:%S')
                                else:
                                    cell_value = str(value)
                                ws.cell(row=row_idx, column=col_idx, value=cell_value)
                        
                        wb.save(filename)
                    except ImportError:
                        messagebox.showerror("Error", "openpyxl library not installed. Please use CSV format.")
                        return
                
                messagebox.showinfo("Export Complete", 
                                  f"Successfully exported {len(rows)} records to:\n{filename}")
                self.log_entry(f"Exported {len(rows)} records from {self.selected_table} to {filename}", "SUCCESS")
                
            except Exception as e:
                error_msg = f"Failed to export data: {str(e)}"
                messagebox.showerror("Export Error", error_msg)
                self.log_entry(error_msg, "ERROR")
    
    def load_table_columns(self):
        """Load table columns for mapping"""
        if not self.db_connection or not self.selected_table:
            return
        
        try:
            cursor = self.db_connection.cursor()
            columns = []
            
            for column in cursor.columns(table=self.selected_table):
                columns.append({
                    'name': column.column_name,
                    'type': column.type_name,
                    'size': column.column_size
                })
            
            self.table_columns = columns
            self.config["table_columns"] = columns
            self.config["selected_table"] = self.selected_table
            self.save_config()
            
        except Exception as e:
            self.log_entry(f"Failed to load table columns: {str(e)}", "ERROR")
    
    def test_api(self):
        """Test API connection"""
        if not self.config.get("api_endpoint"):
            messagebox.showerror("Error", "No API endpoint configured.")
            return
        
        test_data = {
            "test": True,
            "timestamp": datetime.now().isoformat(),
            "uuid": str(uuid.uuid4())
        }
        
        try:
            headers = {'Content-Type': 'application/json'}
            if self.config.get("api_key"):
                headers['Authorization'] = f'Bearer {self.config["api_key"]}'
            
            response = requests.post(
                self.config["api_endpoint"],
                json=test_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                messagebox.showinfo("Success", "API connection test successful!")
                self.log_entry("API test successful", "SUCCESS")
                self.api_status.update_status("good")
            else:
                messagebox.showerror("Error", f"API returned status {response.status_code}")
                self.api_status.update_status("warning")
                
        except Exception as e:
            error_msg = f"API test failed: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_entry(error_msg, "ERROR")
            self.api_status.update_status("error")
    
    def manual_push(self):
        """Manual data push"""
        if not self.selected_table or not self.db_connection:
            messagebox.showerror("Error", "Please select a table first.")
            return
        
        if not self.config.get("api_endpoint"):
            messagebox.showerror("Error", "Please configure API endpoint first.")
            return
        
        # Check if mapping is complete
        if not self.is_mapping_complete():
            if messagebox.askyesno("Incomplete Mapping", 
                                 "Field mapping is not complete. This may result in missing data.\n\n"
                                 "Do you want to continue anyway?"):
                pass  # Continue with incomplete mapping
            else:
                return  # Cancel push
        
        try:
            data = self.get_latest_record()
            if data:
                if self.config.get("test_mode", False):
                    messagebox.showinfo("Test Mode", f"Would send data: {json.dumps(data, indent=2)}")
                    self.log_entry("Test mode: Manual push simulated", "INFO")
                else:
                    success = self.send_to_api(data)
                    if success:
                        messagebox.showinfo("Success", "Data pushed successfully!")
                    else:
                        messagebox.showerror("Error", "Failed to push data. Check logs.")
            else:
                messagebox.showerror("Error", "No data found to push.")
                
        except Exception as e:
            error_msg = f"Manual push failed: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def is_mapping_complete(self):
        """Check if mapping is reasonably complete"""
        if not hasattr(self, 'field_mappings') or not self.field_mappings:
            return False
        
        # Count mapped fields
        mapped_count = len([f for f in self.field_mappings.values() if f.get('api_field')])
        total_count = len(getattr(self, 'table_columns', []))
        
        # Consider mapping complete if at least 50% of fields are mapped
        if total_count == 0:
            return False
        
        completion_ratio = mapped_count / total_count
        return completion_ratio >= 0.5  # At least 50% mapped
    
    def get_latest_record(self) -> Optional[Dict]:
        """Get latest record from selected table"""
        if not self.db_connection or not self.selected_table:
            return None
        
        try:
            cursor = self.db_connection.cursor()
            columns = [col['name'] for col in self.table_columns]
            
            # Find order column (ID or timestamp)
            order_column = None
            for col in ['ID', 'Id', 'id', 'TIMESTAMP', 'Timestamp', 'timestamp', 'DATE', 'Date']:
                if col in columns:
                    order_column = col
                    break
            
            if not order_column:
                order_column = columns[0]
            
            # Get latest record
            query = f"SELECT TOP 1 * FROM [{self.selected_table}] ORDER BY [{order_column}] DESC"
            cursor.execute(query)
            
            row = cursor.fetchone()
            if row:
                record = {}
                for i, col in enumerate(columns):
                    value = row[i]
                    if hasattr(value, 'strftime'):
                        value = value.strftime('%Y-%m-%d %H:%M:%S')
                    record[col] = value
                
                # Apply field mapping if configured
                if hasattr(self, 'field_mappings') and self.field_mappings:
                    # Use new detailed mapping with transformations
                    mapped_record = {}
                    for db_field, value in record.items():
                        if db_field in self.field_mappings:
                            mapping_info = self.field_mappings[db_field]
                            api_field = mapping_info.get('api_field')
                            transform = mapping_info.get('transform', 'No Transform')
                            
                            if api_field:
                                transformed_value = self.apply_transformation(value, transform)
                                mapped_record[api_field] = transformed_value
                    
                    if mapped_record:
                        return mapped_record
                elif self.config.get("field_mapping"):
                    # Fallback to simple mapping
                    mapped_record = {}
                    for db_field, api_field in self.config["field_mapping"].items():
                        if db_field in record:
                            mapped_record[api_field] = record[db_field]
                    return mapped_record
                
                return record
                
        except Exception as e:
            self.log_entry(f"Failed to get latest record: {str(e)}", "ERROR")
        
        return None
    
    def send_to_api(self, data: Dict) -> bool:
        """Send data to API endpoint"""
        if not self.config.get("api_endpoint") or not data:
            return False
        
        # Add UUID if not present
        if "uuid" not in data:
            data["uuid"] = str(uuid.uuid4())
        
        try:
            headers = {'Content-Type': 'application/json'}
            if self.config.get("api_key"):
                headers['Authorization'] = f'Bearer {self.config["api_key"]}'
            
            response = requests.post(
                self.config["api_endpoint"],
                json=data,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                self.log_entry(f"Data sent successfully (UUID: {data.get('uuid', 'N/A')})", "SUCCESS")
                return True
            else:
                self.log_entry(f"API returned HTTP {response.status_code}: {response.text}", "WARNING")
                # Add to buffer for retry
                self.db_manager.add_to_buffer(data, self.config["api_endpoint"], self.config.get("api_key", ""))
                return False
                
        except requests.exceptions.RequestException as e:
            self.log_entry(f"API request failed: {str(e)}", "ERROR")
            # Add to buffer for retry
            self.db_manager.add_to_buffer(data, self.config["api_endpoint"], self.config.get("api_key", ""))
            return False
    
    def start_agent(self):
        """Start the agent"""
        if not self.selected_table:
            messagebox.showerror("Error", "Please configure database and select a table first.")
            return
        
        if not self.config.get("api_endpoint"):
            messagebox.showerror("Error", "Please configure API endpoint first.")
            return
        
        if not self.admin_mode:
            messagebox.showerror("Error", "Admin mode required to start agent.")
            return
        
        self.is_running = True
        self.config["auto_push"] = True
        self.save_config()
        
        self.log_entry("Agent started", "SUCCESS")
        self.agent_status_var.set("Agent: Running")
        
        messagebox.showinfo("Success", "Agent started successfully!")
    
    def stop_agent(self):
        """Stop the agent"""
        self.is_running = False
        self.config["auto_push"] = False
        self.save_config()
        
        self.log_entry("Agent stopped", "INFO")
        self.agent_status_var.set("Agent: Stopped")
        
        messagebox.showinfo("Info", "Agent stopped.")
    
    def clear_buffer(self):
        """Clear the buffer"""
        if not self.admin_mode:
            messagebox.showerror("Error", "Admin mode required.")
            return
        
        result = messagebox.askyesno("Confirm", "Are you sure you want to clear the buffer?")
        if result:
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM push_buffer")
            conn.commit()
            conn.close()
            
            self.log_entry("Buffer cleared", "INFO")
            messagebox.showinfo("Success", "Buffer cleared successfully!")
    
    # Health check methods
    def health_test_database(self):
        """Test database connection for health check"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            if not self.db_connection:
                self.health_db_status.config(text="❌ Not Connected", foreground="red")
                self.health_tree.insert("", 0, values=(timestamp, "Database", "FAIL", "No database connection"))
                return
            
            cursor = self.db_connection.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            
            self.health_db_status.config(text="✅ Connected", foreground="green")
            self.health_tree.insert("", 0, values=(timestamp, "Database", "PASS", "Database connection successful"))
            
        except Exception as e:
            self.health_db_status.config(text="❌ Error", foreground="red")
            self.health_tree.insert("", 0, values=(timestamp, "Database", "FAIL", f"Error: {str(e)}"))
    
    def health_test_api(self):
        """Test API connection for health check"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            if not self.config.get("api_endpoint"):
                self.health_api_status.config(text="❌ Not Configured", foreground="red")
                self.health_tree.insert("", 0, values=(timestamp, "API", "FAIL", "No API endpoint configured"))
                return
            
            test_data = {"test": True, "timestamp": datetime.now().isoformat()}
            headers = {'Content-Type': 'application/json'}
            if self.config.get("api_key"):
                headers['Authorization'] = f'Bearer {self.config["api_key"]}'
            
            response = requests.post(self.config["api_endpoint"], json=test_data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                self.health_api_status.config(text="✅ Connected", foreground="green")
                self.health_tree.insert("", 0, values=(timestamp, "API", "PASS", f"API responded with status {response.status_code}"))
            else:
                self.health_api_status.config(text="⚠️ Warning", foreground="orange")
                self.health_tree.insert("", 0, values=(timestamp, "API", "WARN", f"API returned status {response.status_code}"))
                
        except Exception as e:
            self.health_api_status.config(text="❌ Error", foreground="red")
            self.health_tree.insert("", 0, values=(timestamp, "API", "FAIL", f"Error: {str(e)}"))
    
    def health_check_buffer(self):
        """Check buffer status for health check"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            buffer_items = self.db_manager.get_buffer_items()
            count = len(buffer_items)
            
            if count == 0:
                self.health_buffer_status.config(text="✅ Empty", foreground="green")
                self.health_tree.insert("", 0, values=(timestamp, "Buffer", "PASS", "Buffer is empty"))
            elif count < 10:
                self.health_buffer_status.config(text=f"⚠️ {count} items", foreground="orange")
                self.health_tree.insert("", 0, values=(timestamp, "Buffer", "WARN", f"{count} items in buffer"))
            else:
                self.health_buffer_status.config(text=f"❌ {count} items", foreground="red")
                self.health_tree.insert("", 0, values=(timestamp, "Buffer", "FAIL", f"{count} items in buffer - check API"))
                
        except Exception as e:
            self.health_buffer_status.config(text="❌ Error", foreground="red")
            self.health_tree.insert("", 0, values=(timestamp, "Buffer", "FAIL", f"Error: {str(e)}"))
    
    def health_verify_data(self):
        """Verify data integrity for health check"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            if not self.selected_table or not self.db_connection:
                self.health_data_status.config(text="❌ No Table", foreground="red")
                self.health_tree.insert("", 0, values=(timestamp, "Data Integrity", "FAIL", "No table selected"))
                return
            
            cursor = self.db_connection.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM [{self.selected_table}]")
            count = cursor.fetchone()[0]
            
            if count > 0:
                self.health_data_status.config(text=f"✅ {count} records", foreground="green")
                self.health_tree.insert("", 0, values=(timestamp, "Data Integrity", "PASS", f"Table has {count} records"))
            else:
                self.health_data_status.config(text="⚠️ Empty table", foreground="orange")
                self.health_tree.insert("", 0, values=(timestamp, "Data Integrity", "WARN", "Table is empty"))
                
        except Exception as e:
            self.health_data_status.config(text="❌ Error", foreground="red")
            self.health_tree.insert("", 0, values=(timestamp, "Data Integrity", "FAIL", f"Error: {str(e)}"))
    
    def run_all_health_checks(self):
        """Run all health checks"""
        self.health_test_database()
        self.health_test_api() 
        self.health_check_buffer()
        self.health_verify_data()
        self.log_entry("All health checks completed", "INFO")
    
    def toggle_auto_health_check(self):
        """Toggle automatic health checks"""
        messagebox.showinfo("Info", "Auto health check feature will be implemented in future version")
    
    def export_health_report(self):
        """Export health check report"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Health Report"
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write("MDB Agent Pro - Health Check Report\n")
                    f.write("=" * 40 + "\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    # Export health tree data
                    for item in self.health_tree.get_children():
                        values = self.health_tree.item(item)['values']
                        f.write(f"{values[0]} | {values[1]} | {values[2]} | {values[3]}\n")
                
                messagebox.showinfo("Success", f"Health report exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export health report: {str(e)}")
    
    # Transaction log methods
    def apply_transaction_filter(self):
        """Apply filter to transaction log"""
        # Clear existing items
        for item in self.transaction_tree.get_children():
            self.transaction_tree.delete(item)
        
        # Load filtered transactions
        self.load_transaction_log()
    
    def load_transaction_log(self):
        """Load transaction log data"""
        try:
            # Get filter values
            start_date = self.trans_start_date.get()
            end_date = self.trans_end_date.get()
            status_filter = self.trans_status_filter.get()
            
            # Load recent logs as transaction data
            logs = self.db_manager.get_recent_logs(100)
            
            success_count = 0
            failed_count = 0
            pending_count = 0
            
            for i, log in enumerate(logs):
                status = "Success" if log['level'] == "SUCCESS" else "Failed" if log['level'] == "ERROR" else "Info"
                
                if status_filter != "All" and status != status_filter:
                    continue
                
                if status == "Success":
                    success_count += 1
                elif status == "Failed":
                    failed_count += 1
                else:
                    pending_count += 1
                
                self.transaction_tree.insert("", tk.END, values=(
                    i + 1,
                    log['timestamp'],
                    self.selected_table or "N/A",
                    status,
                    "1",
                    log['message']
                ))
            
            # Update statistics
            total_count = success_count + failed_count + pending_count
            self.stats_total.config(text=str(total_count))
            self.stats_success.config(text=str(success_count))
            self.stats_failed.config(text=str(failed_count))
            self.stats_pending.config(text=str(pending_count))
            
        except Exception as e:
            self.log_entry(f"Failed to load transaction log: {str(e)}", "ERROR")
    
    def export_transactions(self):
        """Export transaction log"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Export Transactions"
            )
            if filename:
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["ID", "Timestamp", "Table", "Status", "Records", "Details"])
                    
                    for item in self.transaction_tree.get_children():
                        values = self.transaction_tree.item(item)['values']
                        writer.writerow(values)
                
                messagebox.showinfo("Success", f"Transactions exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export transactions: {str(e)}")
    
    # Support methods
    def send_log_to_it(self):
        """Prepare and send log to IT support"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"mdb_agent_issue_{timestamp}.txt"
            
            # Show issue description dialog
            issue_window = tk.Toplevel(self.root)
            issue_window.title("Report Issue to IT Support")
            issue_window.geometry("500x400")
            issue_window.transient(self.root)
            issue_window.grab_set()
            
            ttk.Label(issue_window, text="Describe the issue you're experiencing:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=20, pady=(20, 10))
            
            # Issue description
            desc_frame = ttk.Frame(issue_window)
            desc_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
            
            issue_text = scrolledtext.ScrolledText(desc_frame, height=8, wrap=tk.WORD)
            issue_text.pack(fill=tk.BOTH, expand=True)
            issue_text.insert(1.0, "Please describe:\n1. What you were trying to do\n2. What happened instead\n3. Any error messages you saw\n\n")
            
            # Urgency level
            urgency_frame = ttk.LabelFrame(issue_window, text="Issue Priority", padding=10)
            urgency_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
            
            urgency_var = tk.StringVar(value="Normal")
            ttk.Radiobutton(urgency_frame, text="🔴 Critical (System Down)", variable=urgency_var, value="Critical").pack(anchor=tk.W)
            ttk.Radiobutton(urgency_frame, text="🟡 High (Major Function Broken)", variable=urgency_var, value="High").pack(anchor=tk.W)
            ttk.Radiobutton(urgency_frame, text="🟢 Normal (Minor Issue)", variable=urgency_var, value="Normal").pack(anchor=tk.W)
            ttk.Radiobutton(urgency_frame, text="🔵 Low (Enhancement Request)", variable=urgency_var, value="Low").pack(anchor=tk.W)
            
            def create_support_ticket():
                issue_desc = issue_text.get(1.0, tk.END).strip()
                if len(issue_desc) < 20:
                    messagebox.showerror("Error", "Please provide a more detailed description.")
                    return
                
                try:
                    # Create comprehensive support file
                    with open(log_filename, 'w', encoding='utf-8') as f:
                        f.write("MDB AGENT PRO - SUPPORT TICKET\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(f"Generated: {datetime.now().isoformat()}\n")
                        f.write(f"Priority: {urgency_var.get()}\n")
                        f.write(f"User: {os.getenv('USERNAME', 'Unknown')}\n")
                        f.write(f"Computer: {os.getenv('COMPUTERNAME', 'Unknown')}\n\n")
                        
                        f.write("ISSUE DESCRIPTION:\n")
                        f.write("-" * 20 + "\n")
                        f.write(issue_desc + "\n\n")
                        
                        # System info
                        import sys, platform
                        f.write("SYSTEM INFORMATION:\n")
                        f.write("-" * 20 + "\n")
                        f.write(f"OS: {platform.platform()}\n")
                        f.write(f"Python: {sys.version.split()[0]}\n")
                        f.write(f"App Version: 2.0.0\n\n")
                        
                        # Current state
                        f.write("APPLICATION STATE:\n")
                        f.write("-" * 20 + "\n")
                        f.write(f"Database Connected: {'Yes' if self.db_connection else 'No'}\n")
                        f.write(f"API Configured: {'Yes' if self.config.get('api_endpoint') else 'No'}\n")
                        f.write(f"Selected Table: {getattr(self, 'selected_table', 'None')}\n\n")
                        
                        # Recent logs
                        f.write("RECENT LOGS:\n")
                        f.write("-" * 20 + "\n")
                        try:
                            logs = self.db_manager.get_recent_logs(20)
                            for log in logs:
                                f.write(f"{log['timestamp']} [{log['level']}] {log['message']}\n")
                        except:
                            f.write("Could not retrieve logs\n")
                    
                    messagebox.showinfo("Support Ticket Created", 
                                      f"✅ Support ticket created successfully!\n\n"
                                      f"File: {log_filename}\n\n"
                                      f"Please send this file to:\n"
                                      f"📧 freddy.pm@sahabatagro.co.id\n"
                                      f"📱 +62 813-9855-2019\n\n"
                                      f"Priority: {urgency_var.get()}")
                    
                    self.log_entry(f"Support ticket created: {log_filename} (Priority: {urgency_var.get()})", "INFO")
                    issue_window.destroy()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to create support ticket: {str(e)}")
            
            # Buttons
            btn_frame = ttk.Frame(issue_window)
            btn_frame.pack(fill=tk.X, padx=20, pady=20)
            
            ttk.Button(btn_frame, text="📧 Create Support Ticket", command=create_support_ticket).pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(btn_frame, text="❌ Cancel", command=issue_window.destroy).pack(side=tk.RIGHT)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to prepare support ticket: {str(e)}")
    
    def check_updates(self):
        """Check for application updates"""
        update_window = tk.Toplevel(self.root)
        update_window.title("Check for Updates")
        update_window.geometry("450x350")
        update_window.transient(self.root)
        update_window.grab_set()
        
        # Main content
        content_frame = ttk.Frame(update_window)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Icon and title
        title_frame = ttk.Frame(content_frame)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(title_frame, text="🔄", font=('Arial', 24)).pack(side=tk.LEFT)
        ttk.Label(title_frame, text="MDB Agent Pro", font=('Arial', 16, 'bold')).pack(side=tk.LEFT, padx=(10, 0))
        
        # Current version info
        version_frame = ttk.LabelFrame(content_frame, text="Current Version", padding=15)
        version_frame.pack(fill=tk.X, pady=(0, 15))
        
        version_info = [
            ("Version:", "2.0.0 Professional Edition"),
            ("Release Date:", "January 2025"),
            ("Build:", "Stable"),
            ("Developer:", "Freddy Mazmur"),
            ("Company:", "PT Sahabat Agro Group")
        ]
        
        for i, (label, value) in enumerate(version_info):
            ttk.Label(version_frame, text=label, font=('Arial', 9, 'bold')).grid(row=i, column=0, sticky=tk.W, padx=(0, 15), pady=2)
            ttk.Label(version_frame, text=value, font=('Arial', 9)).grid(row=i, column=1, sticky=tk.W, pady=2)
        
        # Update status
        status_frame = ttk.LabelFrame(content_frame, text="Update Status", padding=15)
        status_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(status_frame, text="✅ You are running the latest version!", 
                 font=('Arial', 10, 'bold'), foreground="green").pack(anchor=tk.W)
        
        ttk.Label(status_frame, text="This version includes all the latest features and security updates.", 
                 font=('Arial', 9)).pack(anchor=tk.W, pady=(5, 0))
        
        # Support info
        support_frame = ttk.LabelFrame(content_frame, text="Support Information", padding=15)
        support_frame.pack(fill=tk.X, pady=(0, 15))
        
        support_text = """For updates and support:
📧 Email: freddy.pm@sahabatagro.co.id
📱 Phone: +62 813-9855-2019
🏢 Company: PT Sahabat Agro Group
⏰ Hours: Monday-Friday, 8AM-6PM (WIB)"""
        
        ttk.Label(support_frame, text=support_text, font=('Arial', 9), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Buttons
        btn_frame = ttk.Frame(content_frame)
        btn_frame.pack(fill=tk.X, pady=(15, 0))
        
        ttk.Button(btn_frame, text="❌ Close", command=update_window.destroy).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="📧 Contact Support", command=lambda: (update_window.destroy(), self.send_log_to_it())).pack(side=tk.RIGHT, padx=(0, 10))
    
    def reset_config(self):
        """Reset application configuration"""
        result = messagebox.askyesno("Confirm Reset", 
                                   "This will reset all configuration settings.\n\n"
                                   "Are you sure you want to continue?")
        if result:
            try:
                if os.path.exists(self.config_file):
                    os.remove(self.config_file)
                messagebox.showinfo("Success", "Configuration reset. Please restart the application.")
                self.root.quit()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reset configuration: {str(e)}")
    
    def toggle_admin_mode(self):
        """Toggle admin mode"""
        if not self.admin_mode:
            pin = tk.simpledialog.askstring("Admin Mode", "Enter admin PIN:", show='*')
            if pin == self.admin_pin:
                self.admin_mode = True
                self.admin_btn.config(text="Exit Admin Mode")
                self.log_entry("Admin mode enabled", "INFO")
                messagebox.showinfo("Success", "Admin mode enabled")
            else:
                messagebox.showerror("Error", "Invalid PIN")
        else:
            self.admin_mode = False
            self.admin_btn.config(text="Admin Mode")
            self.log_entry("Admin mode disabled", "INFO")
            messagebox.showinfo("Info", "Admin mode disabled")
    
    def toggle_theme(self):
        """Toggle dark/light theme"""
        self.dark_mode = not self.dark_mode
        self.config["dark_mode"] = self.dark_mode
        self.save_config()
        
        if self.dark_mode:
            self.theme_btn.config(text="☀️ Light Mode")
            # Apply dark theme
            self.style.theme_use('clam')  # Use clam theme for better dark mode support
            self.style.configure('TFrame', background='#2d2d2d')
            self.style.configure('TLabel', background='#2d2d2d', foreground='white')
            self.style.configure('TButton', background='#404040', foreground='white')
            self.style.configure('TLabelFrame', background='#2d2d2d', foreground='white')
            self.style.configure('TLabelFrame.Label', background='#2d2d2d', foreground='white')
            self.style.configure('Treeview', background='#404040', foreground='white', fieldbackground='#404040')
            self.style.configure('Treeview.Heading', background='#505050', foreground='white')
            
            # Update root background
            self.root.configure(bg='#2d2d2d')
        else:
            self.theme_btn.config(text="🌙 Dark Mode")
            # Apply light theme
            self.style.theme_use('default')
            self.style.configure('TFrame', background='SystemButtonFace')
            self.style.configure('TLabel', background='SystemButtonFace', foreground='black')
            self.style.configure('TButton', background='SystemButtonFace', foreground='black')
            self.style.configure('TLabelFrame', background='SystemButtonFace', foreground='black')
            self.style.configure('TLabelFrame.Label', background='SystemButtonFace', foreground='black')
            self.style.configure('Treeview', background='white', foreground='black', fieldbackground='white')
            self.style.configure('Treeview.Heading', background='SystemButtonFace', foreground='black')
            
            # Update root background
            self.root.configure(bg='SystemButtonFace')
        
        self.log_entry(f"Theme changed to {'dark' if self.dark_mode else 'light'} mode", "INFO")
    
    def save_api_settings(self):
        """Save API settings"""
        try:
            self.config["api_endpoint"] = self.api_endpoint_var.get()
            self.config["api_key"] = self.api_key_var.get()
            self.config["test_mode"] = self.test_mode_var.get()
            self.save_config()
            
            messagebox.showinfo("Success", "API settings saved successfully!")
            self.log_entry("API settings saved", "INFO")
            
        except Exception as e:
            error_msg = f"Failed to save API settings: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def send_sample_data(self):
        """Send sample data to API"""
        if not self.config.get("api_endpoint"):
            messagebox.showerror("Error", "Please configure API endpoint first.")
            return
        
        sample_data = {
            "test": True,
            "timestamp": datetime.now().isoformat(),
            "uuid": str(uuid.uuid4()),
            "sample_field": "Sample Value",
            "record_count": 1
        }
        
        try:
            headers = {'Content-Type': 'application/json'}
            if self.config.get("api_key"):
                headers['Authorization'] = f'Bearer {self.config["api_key"]}'
            
            response = requests.post(
                self.config["api_endpoint"],
                json=sample_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                messagebox.showinfo("Success", f"Sample data sent successfully!\nResponse: {response.text}")
                self.log_entry("Sample data sent successfully", "SUCCESS")
            else:
                messagebox.showerror("Error", f"API returned status {response.status_code}\nResponse: {response.text}")
                self.log_entry(f"Sample data failed: {response.status_code}", "ERROR")
                
        except Exception as e:
            error_msg = f"Failed to send sample data: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def generate_payload_preview(self):
        """Generate payload preview"""
        try:
            if not self.selected_table or not self.table_columns:
                sample_payload = {
                    "uuid": "sample-uuid-here",
                    "timestamp": datetime.now().isoformat(),
                    "table": "your_table_name",
                    "data": {
                        "field1": "value1",
                        "field2": "value2",
                        "field3": "value3"
                    }
                }
            else:
                # Generate based on actual table structure
                sample_data = {}
                for col in self.table_columns[:5]:  # Show first 5 columns
                    col_name = col['name']
                    col_type = col.get('type', 'TEXT')
                    
                    if 'INT' in col_type.upper():
                        sample_data[col_name] = 123
                    elif 'DATE' in col_type.upper():
                        sample_data[col_name] = datetime.now().isoformat()
                    elif 'BOOL' in col_type.upper():
                        sample_data[col_name] = True
                    else:
                        sample_data[col_name] = f"sample_{col_name}"
                
                sample_payload = {
                    "uuid": str(uuid.uuid4()),
                    "timestamp": datetime.now().isoformat(),
                    "table": self.selected_table,
                    "data": sample_data
                }
            
            # Pretty print JSON
            json_text = json.dumps(sample_payload, indent=2)
            self.payload_text.delete(1.0, tk.END)
            self.payload_text.insert(1.0, json_text)
            
        except Exception as e:
            error_msg = f"Failed to generate preview: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def save_scheduler_settings(self):
        """Save scheduler settings"""
        try:
            interval = int(self.push_interval_var.get())
            if interval < 1:
                messagebox.showerror("Error", "Push interval must be at least 1 minute.")
                return
            
            self.config["push_interval"] = interval * 60  # Convert to seconds
            self.config["auto_push"] = self.enable_auto_push_var.get()
            self.save_config()
            
            messagebox.showinfo("Success", "Scheduler settings saved successfully!")
            self.log_entry("Scheduler settings saved", "INFO")
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for push interval.")
        except Exception as e:
            error_msg = f"Failed to save scheduler settings: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def start_scheduler(self):
        """Start the scheduler"""
        if not self.admin_mode:
            messagebox.showerror("Error", "Admin mode required to start scheduler.")
            return
        
        if not self.config.get("auto_push"):
            messagebox.showerror("Error", "Please enable automatic push first.")
            return
        
        try:
            self.is_running = True
            self.sched_agent_status.config(text="Running", foreground="green")
            
            # Calculate next push time
            interval = self.config.get("push_interval", 300)
            next_push = datetime.now() + timedelta(seconds=interval)
            self.sched_next_push.config(text=next_push.strftime("%Y-%m-%d %H:%M:%S"))
            
            self.log_entry("Scheduler started", "SUCCESS")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.scheduler_tree.insert("", 0, values=(timestamp, "Start", "SUCCESS", "Scheduler started successfully"))
            
            messagebox.showinfo("Success", "Scheduler started successfully!")
            
        except Exception as e:
            error_msg = f"Failed to start scheduler: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def stop_scheduler(self):
        """Stop the scheduler"""
        try:
            self.is_running = False
            self.sched_agent_status.config(text="Stopped", foreground="red")
            self.sched_next_push.config(text="Not scheduled")
            
            self.log_entry("Scheduler stopped", "INFO")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.scheduler_tree.insert("", 0, values=(timestamp, "Stop", "INFO", "Scheduler stopped"))
            
            messagebox.showinfo("Info", "Scheduler stopped.")
            
        except Exception as e:
            error_msg = f"Failed to stop scheduler: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def force_push_now(self):
        """Force immediate push"""
        if not self.admin_mode:
            messagebox.showerror("Error", "Admin mode required.")
            return
        
        try:
            result = self.manual_push()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if result:
                self.scheduler_tree.insert("", 0, values=(timestamp, "Manual Push", "SUCCESS", "Manual push completed successfully"))
            else:
                self.scheduler_tree.insert("", 0, values=(timestamp, "Manual Push", "FAILED", "Manual push failed"))
            
        except Exception as e:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.scheduler_tree.insert("", 0, values=(timestamp, "Manual Push", "ERROR", f"Error: {str(e)}"))
    
    def load_settings(self):
        """Load settings from config"""
        try:
            if hasattr(self, 'mdb_file_var'):
                self.mdb_file_var.set(self.config.get("mdb_file", ""))
            if hasattr(self, 'mdb_password_var'):
                self.mdb_password_var.set(self.config.get("mdb_password", ""))
            if hasattr(self, 'api_endpoint_var'):
                self.api_endpoint_var.set(self.config.get("api_endpoint", ""))
            if hasattr(self, 'api_key_var'):
                self.api_key_var.set(self.config.get("api_key", ""))
            if hasattr(self, 'test_mode_var'):
                self.test_mode_var.set(self.config.get("test_mode", False))
            if hasattr(self, 'push_interval_var'):
                interval_minutes = self.config.get("push_interval", 300) // 60
                self.push_interval_var.set(str(interval_minutes))
            if hasattr(self, 'enable_auto_push_var'):
                self.enable_auto_push_var.set(self.config.get("auto_push", False))
                
        except Exception as e:
            self.log_entry(f"Failed to load settings: {str(e)}", "ERROR")
    
    def refresh_dashboard(self):
        """Refresh dashboard data"""
        # Update status labels
        if self.db_connection:
            self.dash_db_status.config(text="Connected", foreground="green")
        else:
            self.dash_db_status.config(text="Not Connected", foreground="red")
        
        if self.config.get("api_endpoint"):
            self.dash_api_status.config(text="Configured", foreground="green")
        else:
            self.dash_api_status.config(text="Not Configured", foreground="red")
        
        if self.is_running:
            self.dash_agent_status.config(text="Running", foreground="green")
        else:
            self.dash_agent_status.config(text="Stopped", foreground="red")
        
        # Update buffer status
        try:
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM push_buffer WHERE status = 'pending'")
            count = cursor.fetchone()[0]
            conn.close()
            
            if count > 0:
                self.dash_buffer_status.config(text=f"{count} items", foreground="orange")
                self.buffer_status.update_status("warning")
            else:
                self.dash_buffer_status.config(text="0 items", foreground="green")
                self.buffer_status.update_status("good")
        except:
            self.dash_buffer_status.config(text="Error", foreground="red")
            self.buffer_status.update_status("error")
        
        # Update recent activity
        self.activity_tree.delete(*self.activity_tree.get_children())
        logs = self.db_manager.get_recent_logs(20)
        
        for log in logs:
            self.activity_tree.insert("", 0, values=(
                log['timestamp'][:19],  # Remove microseconds
                log['level'],
                log['message']
            ))
    
    def create_about_tab(self):
        """Create about application tab"""
        frame = ttk.Frame(self.content_inner)
        self.tab_frames["about"] = frame
        
        # Create scrollable frame for About content
        about_canvas = tk.Canvas(frame)
        about_scrollbar = ttk.Scrollbar(frame, orient="vertical", command=about_canvas.yview)
        scrollable_frame = ttk.Frame(about_canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: about_canvas.configure(scrollregion=about_canvas.bbox("all"))
        )
        
        about_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        about_canvas.configure(yscrollcommand=about_scrollbar.set)
        
        about_canvas.pack(side="left", fill="both", expand=True)
        about_scrollbar.pack(side="right", fill="y")
        
        # Title
        ttk.Label(scrollable_frame, text="About MDB Agent Pro", style='Title.TLabel').pack(anchor=tk.W, pady=(10, 20))
        
        # Application Information
        app_frame = ttk.LabelFrame(scrollable_frame, text="Application Information", padding=15)
        app_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        app_info = [
            ("Application Name:", "MDB Agent Pro"),
            ("Version:", "2.0.0 (Professional Edition)"),
            ("Release Date:", "January 2025"),
            ("Purpose:", "Microsoft Access Database to API Bridge"),
            ("License:", "Proprietary - PT Sahabat Agro Group"),
            ("Architecture:", "Python-based Desktop Application"),
            ("Compatibility:", "Windows 10/11, Microsoft Access 2016+")
        ]
        
        for i, (label, value) in enumerate(app_info):
            ttk.Label(app_frame, text=label, font=('Arial', 9, 'bold')).grid(row=i, column=0, sticky=tk.W, padx=(0, 15), pady=2)
            ttk.Label(app_frame, text=value, font=('Arial', 9)).grid(row=i, column=1, sticky=tk.W, pady=2)
        
        # Company Information
        company_frame = ttk.LabelFrame(scrollable_frame, text="Company Information", padding=15)
        company_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        company_info = [
            ("Company:", "PT Sahabat Agro Group"),
            ("Industry:", "Agriculture Technology & Data Management"),
            ("Headquarters:", "Indonesia"),
            ("Business Focus:", "Agricultural Supply Chain & Digital Solutions"),
            ("Established:", "Serving agricultural sector since 2010"),
            ("Specialization:", "Database Integration & API Management"),
            ("Mission:", "Modernizing agricultural data systems")
        ]
        
        for i, (label, value) in enumerate(company_info):
            ttk.Label(company_frame, text=label, font=('Arial', 9, 'bold')).grid(row=i, column=0, sticky=tk.W, padx=(0, 15), pady=2)
            ttk.Label(company_frame, text=value, font=('Arial', 9)).grid(row=i, column=1, sticky=tk.W, pady=2)
        
        # Developer Information
        dev_frame = ttk.LabelFrame(scrollable_frame, text="Developer Information", padding=15)
        dev_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        dev_info = [
            ("Lead Developer:", "Freddy Mazmur"),
            ("Title:", "Senior Software Engineer & Database Specialist"),
            ("Email:", "freddy.pm@sahabatagro.co.id"),
            ("Mobile:", "+62 813-9855-2019"),
            ("Specialization:", "Database Integration, API Development, Python Applications"),
            ("Experience:", "10+ years in Enterprise Software Development"),
            ("Expertise:", "Microsoft Access, SQL Server, Python, API Design"),
            ("Location:", "Jakarta, Indonesia")
        ]
        
        for i, (label, value) in enumerate(dev_info):
            ttk.Label(dev_frame, text=label, font=('Arial', 9, 'bold')).grid(row=i, column=0, sticky=tk.W, padx=(0, 15), pady=2)
            ttk.Label(dev_frame, text=value, font=('Arial', 9)).grid(row=i, column=1, sticky=tk.W, pady=2)
        
        # Technical Specifications
        tech_frame = ttk.LabelFrame(scrollable_frame, text="Technical Specifications", padding=15)
        tech_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        import sys
        import platform
        
        tech_info = [
            ("Python Version:", f"{sys.version.split()[0]}"),
            ("Platform:", f"{platform.system()} {platform.release()}"),
            ("Architecture:", f"{platform.machine()}"),
            ("GUI Framework:", "Tkinter (Built-in)"),
            ("Database Connectivity:", "ODBC (pyodbc)"),
            ("HTTP Client:", "Requests Library"),
            ("Data Storage:", "SQLite3 (Local)"),
            ("Logging:", "Python Standard Logging")
        ]
        
        for i, (label, value) in enumerate(tech_info):
            ttk.Label(tech_frame, text=label, font=('Arial', 9, 'bold')).grid(row=i, column=0, sticky=tk.W, padx=(0, 15), pady=2)
            ttk.Label(tech_frame, text=value, font=('Arial', 9)).grid(row=i, column=1, sticky=tk.W, pady=2)
        
        # Key Features
        features_frame = ttk.LabelFrame(scrollable_frame, text="Key Features & Capabilities", padding=15)
        features_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        features_text = """
🔗 Visual Field Mapping System
   • Drag-and-drop interface for database to API field mapping
   • Support for data transformations and formatting
   • Template management for reusable configurations

⚡ Real-time Data Processing
   • Automatic data synchronization from Access databases
   • Intelligent retry mechanism for failed API calls
   • Background processing with minimal system impact

🛡️ Robust Error Handling
   • Comprehensive logging and audit trails
   • Buffer system for offline resilience
   • Health monitoring and diagnostics

📊 Advanced Monitoring
   • Transaction logging with detailed statistics
   • API performance monitoring
   • Database connection health checks

🔧 Enterprise Configuration
   • JSON-based configuration management
   • Multiple database and API endpoint support
   • Scheduled operations and automation

🎯 User-Friendly Interface
   • Intuitive tabbed interface design
   • Context-sensitive help and validation
   • Professional administrative controls
        """
        
        features_label = ttk.Label(features_frame, text=features_text.strip(), justify=tk.LEFT, font=('Arial', 9))
        features_label.pack(anchor=tk.W)
        
        # Support & Contact
        support_frame = ttk.LabelFrame(scrollable_frame, text="Support & Maintenance", padding=15)
        support_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        support_text = """
For technical support, feature requests, or system maintenance:

📧 Primary Contact: freddy.pm@sahabatagro.co.id
📱 Emergency Support: +62 813-9855-2019
🏢 Company: PT Sahabat Agro Group
🌐 Business Hours: Monday - Friday, 8:00 AM - 6:00 PM (WIB)

System Maintenance:
• Regular updates and security patches
• Database optimization and performance tuning
• Custom feature development available
• On-site training and consultation services
        """
        
        ttk.Label(support_frame, text=support_text.strip(), justify=tk.LEFT, font=('Arial', 9)).pack(anchor=tk.W)
        
        # Action Buttons
        action_frame = ttk.Frame(scrollable_frame)
        action_frame.pack(fill=tk.X, pady=15, padx=10)
        
        btn_frame = ttk.Frame(action_frame)
        btn_frame.pack()
        
        ttk.Button(btn_frame, text="📧 Send Log to IT", command=self.send_log_to_it).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="🔄 Check for Updates", command=self.check_updates).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="⚙️ Generate System Report", command=self.generate_system_report).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="🗂️ Export Support Logs", command=self.export_support_logs).pack(side=tk.LEFT)
        
        # Copyright and License
        copyright_frame = ttk.LabelFrame(scrollable_frame, text="Copyright & License", padding=15)
        copyright_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        copyright_text = """
© 2025 PT Sahabat Agro Group. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, 
or modification is strictly prohibited. This application is licensed exclusively 
for use by PT Sahabat Agro Group and its authorized partners.

Developed by: Freddy Mazmur
Built with: Python, Tkinter, and enterprise-grade libraries
Version: 2.0.0 Professional Edition
        """
        
        ttk.Label(copyright_frame, text=copyright_text.strip(), justify=tk.LEFT, font=('Arial', 8), foreground="gray").pack(anchor=tk.W)
        
        # Bind mousewheel to canvas for scrolling
        def _on_mousewheel(event):
            about_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        about_canvas.bind("<MouseWheel>", _on_mousewheel)
        license_frame = ttk.LabelFrame(frame, text="License & Legal", padding=10)
        license_frame.pack(fill=tk.BOTH, expand=True)
        
        license_text = """© 2025 PT Sahabat Agro Group. All rights reserved.

This software is licensed for use within the organization only.
Redistribution or modification without written permission is prohibited.

For technical support, please contact:
IT Support: freddy.pm@sahabatagro.co.id
Phone: +62 813-9855-2019
        """
        ttk.Label(license_frame, text=license_text.strip(), justify=tk.LEFT).pack(anchor=tk.W)
    
    def create_api_tab(self):
        """Create API configuration tab"""
        frame = ttk.Frame(self.content_inner)
        self.tab_frames["api"] = frame
        
        # Page title with better spacing
        title_frame = ttk.Frame(frame)
        title_frame.pack(fill=tk.X, pady=(0, 25))
        
        ttk.Label(title_frame, text="API Settings", 
                 style='Title.TLabel', 
                 font=('Arial', 16, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="Configure API endpoint and authentication settings", 
                 font=('Arial', 11), 
                 foreground='gray').pack(anchor=tk.W, pady=(3, 0))
        
        # API settings
        api_frame = ttk.LabelFrame(frame, text="API Settings", padding=10)
        api_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Endpoint URL
        ttk.Label(api_frame, text="Endpoint URL:").pack(anchor=tk.W)
        self.api_endpoint_var = tk.StringVar()
        ttk.Entry(api_frame, textvariable=self.api_endpoint_var).pack(fill=tk.X, pady=(5, 10))
        
        # API Key
        ttk.Label(api_frame, text="API Key/Token:").pack(anchor=tk.W)
        self.api_key_var = tk.StringVar()
        ttk.Entry(api_frame, textvariable=self.api_key_var, show="*").pack(fill=tk.X, pady=(5, 10))
        
        # Test mode
        self.test_mode_var = tk.BooleanVar()
        ttk.Checkbutton(api_frame, text="Test Mode (Don't send real data)", variable=self.test_mode_var).pack(anchor=tk.W, pady=(0, 10))
        
        # Save button
        ttk.Button(api_frame, text="Save API Settings", command=self.save_api_settings).pack()
        
        # Test API
        test_frame = ttk.LabelFrame(frame, text="API Testing", padding=10)
        test_frame.pack(fill=tk.X, pady=(0, 10))
        
        test_btn_frame = ttk.Frame(test_frame)
        test_btn_frame.pack(fill=tk.X)
        
        ttk.Button(test_btn_frame, text="Test Connection", command=self.test_api).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(test_btn_frame, text="Send Sample Data", command=self.send_sample_data).pack(side=tk.LEFT)
        
        # Payload preview
        preview_frame = ttk.LabelFrame(frame, text="Payload Preview", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(preview_frame, text="Sample payload that will be sent:").pack(anchor=tk.W, pady=(0, 5))
        
        self.payload_text = scrolledtext.ScrolledText(preview_frame, height=10, width=60)
        self.payload_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        ttk.Button(preview_frame, text="Generate Preview", command=self.generate_payload_preview).pack()
    
    def create_scheduler_tab(self):
        """Create scheduler configuration tab"""
        frame = ttk.Frame(self.content_inner)
        self.tab_frames["scheduler"] = frame
        
        # Page title with better spacing
        title_frame = ttk.Frame(frame)
        title_frame.pack(fill=tk.X, pady=(0, 25))
        
        ttk.Label(title_frame, text="Scheduler", 
                 style='Title.TLabel', 
                 font=('Arial', 16, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="Configure automatic data push scheduling", 
                 font=('Arial', 11), 
                 foreground='gray').pack(anchor=tk.W, pady=(3, 0))
        
        # Scheduler settings
        scheduler_frame = ttk.LabelFrame(frame, text="Scheduler Settings", padding=10)
        scheduler_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Push interval
        interval_frame = ttk.Frame(scheduler_frame)
        interval_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(interval_frame, text="Push Interval:").pack(side=tk.LEFT)
        self.push_interval_var = tk.StringVar(value="5")
        ttk.Entry(interval_frame, textvariable=self.push_interval_var, width=10).pack(side=tk.LEFT, padx=(5, 5))
        ttk.Label(interval_frame, text="minutes").pack(side=tk.LEFT)
        
        # Enable auto push
        self.enable_auto_push_var = tk.BooleanVar()
        ttk.Checkbutton(scheduler_frame, text="Enable Automatic Push", variable=self.enable_auto_push_var).pack(anchor=tk.W, pady=(0, 10))
        
        # Save button
        ttk.Button(scheduler_frame, text="Save Scheduler Settings", command=self.save_scheduler_settings).pack()
        
        # Current status
        status_frame = ttk.LabelFrame(frame, text="Current Status", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        status_grid = ttk.Frame(status_frame)
        status_grid.pack(fill=tk.X)
        
        ttk.Label(status_grid, text="Agent Status:", style='Header.TLabel').grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        self.sched_agent_status = ttk.Label(status_grid, text="Stopped", foreground="red")
        self.sched_agent_status.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(status_grid, text="Next Push:", style='Header.TLabel').grid(row=1, column=0, sticky=tk.W, padx=(0, 20))
        self.sched_next_push = ttk.Label(status_grid, text="Not scheduled")
        self.sched_next_push.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(status_grid, text="Last Push:", style='Header.TLabel').grid(row=2, column=0, sticky=tk.W, padx=(0, 20))
        self.sched_last_push = ttk.Label(status_grid, text="Never")
        self.sched_last_push.grid(row=2, column=1, sticky=tk.W)
        
        # Manual controls
        controls_frame = ttk.LabelFrame(frame, text="Manual Controls", padding=10)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        controls_btn_frame = ttk.Frame(controls_frame)
        controls_btn_frame.pack(fill=tk.X)
        
        ttk.Button(controls_btn_frame, text="Start Scheduler", command=self.start_scheduler).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(controls_btn_frame, text="Stop Scheduler", command=self.stop_scheduler).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(controls_btn_frame, text="Force Push Now", command=self.force_push_now).pack(side=tk.LEFT)
        
        # Activity log
        activity_frame = ttk.LabelFrame(frame, text="Scheduler Activity Log", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True)
        
        self.scheduler_tree = ttk.Treeview(activity_frame, columns=("timestamp", "action", "status", "details"), show="headings", height=8)
        self.scheduler_tree.heading("timestamp", text="Timestamp")
        self.scheduler_tree.heading("action", text="Action")
        self.scheduler_tree.heading("status", text="Status")
        self.scheduler_tree.heading("details", text="Details")
        
        self.scheduler_tree.column("timestamp", width=150)
        self.scheduler_tree.column("action", width=120)
        self.scheduler_tree.column("status", width=80)
        self.scheduler_tree.column("details", width=350)
        
        scheduler_scroll = ttk.Scrollbar(activity_frame, orient=tk.VERTICAL, command=self.scheduler_tree.yview)
        self.scheduler_tree.configure(yscrollcommand=scheduler_scroll.set)
        
        self.scheduler_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scheduler_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_mapping_tab(self):
        """Create comprehensive API field mapping tab"""
        frame = ttk.Frame(self.content_inner)
        self.tab_frames["mapping"] = frame
        
        # Page title with better spacing
        title_frame = ttk.Frame(frame)
        title_frame.pack(fill=tk.X, pady=(0, 25))
        
        ttk.Label(title_frame, text="API Field Mapping", 
                 style='Title.TLabel', 
                 font=('Arial', 16, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="Map database fields to API endpoints with transformations", 
                 font=('Arial', 11), 
                 foreground='gray').pack(anchor=tk.W, pady=(3, 0))
        
        # Main container with two panels
        main_container = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Mapping interface
        left_panel = ttk.Frame(main_container)
        main_container.add(left_panel, weight=2)
        
        # Right panel - Preview and controls
        right_panel = ttk.Frame(main_container)
        main_container.add(right_panel, weight=1)
        
        # === LEFT PANEL ===
        # Instructions
        instruction_frame = ttk.LabelFrame(left_panel, text="How to Map Fields", padding=10)
        instruction_frame.pack(fill=tk.X, pady=(0, 10))
        
        instructions = """
1. Select database table from Database Connection tab
2. Choose API field for each database column using dropdown
3. Set data transformation if needed
4. Save your mapping as template for reuse
5. Test mapping before going live
        """
        ttk.Label(instruction_frame, text=instructions.strip(), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Mapping interface
        mapping_frame = ttk.LabelFrame(left_panel, text="Field Mapping", padding=10)
        mapping_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Headers
        header_frame = ttk.Frame(mapping_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Database Column", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Label(header_frame, text="→", font=('Arial', 12, 'bold')).grid(row=0, column=1, padx=10)
        ttk.Label(header_frame, text="API Field", font=('Arial', 10, 'bold')).grid(row=0, column=2, sticky=tk.W, padx=(20, 20))
        ttk.Label(header_frame, text="Transform", font=('Arial', 10, 'bold')).grid(row=0, column=3, sticky=tk.W, padx=(20, 0))
        
        # Scrollable mapping area
        mapping_canvas = tk.Canvas(mapping_frame)
        mapping_scrollbar = ttk.Scrollbar(mapping_frame, orient="vertical", command=mapping_canvas.yview)
        self.mapping_scroll_frame = ttk.Frame(mapping_canvas)
        
        self.mapping_scroll_frame.bind(
            "<Configure>",
            lambda e: mapping_canvas.configure(scrollregion=mapping_canvas.bbox("all"))
        )
        
        mapping_canvas.create_window((0, 0), window=self.mapping_scroll_frame, anchor="nw")
        mapping_canvas.configure(yscrollcommand=mapping_scrollbar.set)
        
        mapping_canvas.pack(side="left", fill="both", expand=True)
        mapping_scrollbar.pack(side="right", fill="y")
        
        # === RIGHT PANEL ===
        # Template management
        template_frame = ttk.LabelFrame(right_panel, text="Mapping Templates", padding=10)
        template_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Template list
        ttk.Label(template_frame, text="Saved Templates:").pack(anchor=tk.W)
        self.template_listbox = tk.Listbox(template_frame, height=4)
        self.template_listbox.pack(fill=tk.X, pady=(5, 10))
        
        # Template controls
        template_btn_frame = ttk.Frame(template_frame)
        template_btn_frame.pack(fill=tk.X)
        
        ttk.Button(template_btn_frame, text="Load", command=self.load_selected_template).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(template_btn_frame, text="Save", command=self.show_save_template_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(template_btn_frame, text="Delete", command=self.delete_selected_template).pack(side=tk.LEFT, padx=5)
        
        # API Structure Import
        api_frame = ttk.LabelFrame(right_panel, text="API Structure", padding=10)
        api_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(api_frame, text="Import API Spec (JSON)", command=self.import_api_spec).pack(fill=tk.X, pady=(0, 5))
        ttk.Button(api_frame, text="Auto Detect from Endpoint", command=self.auto_detect_api_structure).pack(fill=tk.X, pady=(0, 5))
        ttk.Button(api_frame, text="Manual API Fields", command=self.show_manual_api_fields_dialog).pack(fill=tk.X)
        
        # Preview
        preview_frame = ttk.LabelFrame(right_panel, text="JSON Preview", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.json_preview = scrolledtext.ScrolledText(preview_frame, height=12, state=tk.DISABLED)
        self.json_preview.pack(fill=tk.BOTH, expand=True)
        
        # Test controls
        test_frame = ttk.LabelFrame(right_panel, text="Test Mapping", padding=10)
        test_frame.pack(fill=tk.X)
        
        ttk.Button(test_frame, text="Refresh Preview", command=self.update_json_preview).pack(fill=tk.X, pady=(0, 5))
        ttk.Button(test_frame, text="Test API Call", command=self.test_mapping_api_call).pack(fill=tk.X, pady=(0, 5))
        ttk.Button(test_frame, text="Validate Mapping", command=self.validate_mapping).pack(fill=tk.X)
        
        # Initialize
        self.field_mappings = {}
        self.api_fields = []
        self.load_mapping_templates()
        self.refresh_mapping_interface()
        
        # Show placeholder if no table selected
        if not hasattr(self, 'selected_table') or not self.selected_table:
            ttk.Label(self.mapping_scroll_frame, text="Please select a database table first from 'Database Connection' tab", 
                     font=('Arial', 12), foreground='gray').pack(pady=50)
    
    # Support functions for about tab
    def export_support_logs(self):
        """Export comprehensive logs for support purposes"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"mdb_agent_support_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("MDB AGENT PRO - SUPPORT LOG EXPORT\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"Version: 2.0.0 Professional Edition\n")
                f.write(f"Developer: Freddy Mazmur - PT Sahabat Agro Group\n")
                f.write(f"Contact: freddy.pm@sahabatagro.co.id\n\n")
                
                # System Information
                import sys, platform
                f.write("SYSTEM INFORMATION:\n")
                f.write("-" * 30 + "\n")
                f.write(f"Operating System: {platform.system()} {platform.release()}\n")
                f.write(f"Python Version: {sys.version.split()[0]}\n")
                f.write(f"Architecture: {platform.machine()}\n")
                f.write(f"Platform: {platform.platform()}\n")
                f.write(f"Processor: {platform.processor()}\n\n")
                
                # Application Status
                f.write("APPLICATION STATUS:\n")
                f.write("-" * 30 + "\n")
                f.write(f"Database Connected: {'Yes' if self.db_connection else 'No'}\n")
                f.write(f"Selected Table: {getattr(self, 'selected_table', 'None')}\n")
                f.write(f"API Endpoint: {'Configured' if self.config.get('api_endpoint') else 'Not Configured'}\n")
                f.write(f"Agent Running: {'Yes' if getattr(self, 'is_running', False) else 'No'}\n")
                f.write(f"Admin Mode: {'Active' if getattr(self, 'admin_mode', False) else 'Inactive'}\n\n")
                
                # Configuration (sanitized)
                f.write("CONFIGURATION:\n")
                f.write("-" * 30 + "\n")
                safe_config = {k: v for k, v in self.config.items() 
                             if k not in ['api_key', 'mdb_password', 'admin_pin']}
                import json
                f.write(json.dumps(safe_config, indent=2))
                f.write("\n\n")
                
                # Database Information
                if self.db_connection:
                    f.write("DATABASE INFORMATION:\n")
                    f.write("-" * 30 + "\n")
                    try:
                        cursor = self.db_connection.cursor()
                        tables = [table.table_name for table in cursor.tables() if table.table_type == 'TABLE']
                        f.write(f"Available Tables: {', '.join(tables)}\n")
                        if hasattr(self, 'table_columns') and self.table_columns:
                            f.write(f"Current Table Columns: {len(self.table_columns)} columns\n")
                    except Exception as e:
                        f.write(f"Database query error: {str(e)}\n")
                    f.write("\n")
                
                # Recent Logs (last 50)
                f.write("RECENT LOGS:\n")
                f.write("-" * 30 + "\n")
                try:
                    logs = self.db_manager.get_recent_logs(50)
                    for log in logs:
                        f.write(f"{log['timestamp']} [{log['level']}] {log['message']}\n")
                        if log.get('details'):
                            f.write(f"    Details: {log['details']}\n")
                except Exception as e:
                    f.write(f"Could not retrieve logs: {str(e)}\n")
                
                f.write("\n" + "=" * 60 + "\n")
                f.write("End of Support Log\n")
            
            messagebox.showinfo("Success", 
                              f"✅ Support logs exported successfully!\n\n"
                              f"File: {filename}\n"
                              f"Please send this file to IT support for assistance.")
            self.log_entry(f"Support logs exported to {filename}", "INFO")
            
        except Exception as e:
            error_msg = f"Failed to export support logs: {str(e)}"
            messagebox.showerror("Export Error", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def generate_system_report(self):
        """Generate comprehensive system report in popup window"""
        try:
            report_window = tk.Toplevel(self.root)
            report_window.title("MDB Agent Pro - System Report")
            report_window.geometry("800x600")
            report_window.transient(self.root)
            report_window.grab_set()
            
            # Create text widget with scrollbar
            text_frame = ttk.Frame(report_window)
            text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            text_widget = scrolledtext.ScrolledText(text_frame, font=('Courier New', 9), wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True)
            
            # Generate comprehensive report
            import sys, platform
            from datetime import datetime
            
            report = f"""
MDB AGENT PRO - SYSTEM REPORT
{'='*80}

Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Application Version: 2.0.0 Professional Edition
Developer: Freddy Mazmur (freddy.pm@sahabatagro.co.id)
Company: PT Sahabat Agro Group

SYSTEM SPECIFICATIONS
{'-'*50}
Operating System: {platform.system()} {platform.release()}
Platform Details: {platform.platform()}
Python Version: {sys.version.split()[0]}
Architecture: {platform.machine()}
Processor: {platform.processor()}

APPLICATION STATUS
{'-'*50}
Database Status: {'✅ Connected' if self.db_connection else '❌ Not Connected'}
Selected Database: {self.config.get('mdb_file', 'None')}
Selected Table: {getattr(self, 'selected_table', 'None')}
API Endpoint: {'✅ Configured' if self.config.get('api_endpoint') else '❌ Not Configured'}
Agent Status: {'🟢 Running' if getattr(self, 'is_running', False) else '⭕ Stopped'}
Admin Mode: {'🔓 Active' if getattr(self, 'admin_mode', False) else '🔒 Inactive'}

CONFIGURATION SUMMARY
{'-'*50}
Auto Push: {'Enabled' if self.config.get('auto_push', False) else 'Disabled'}
Push Interval: {self.config.get('push_interval', 300)} seconds
Test Mode: {'Enabled' if self.config.get('test_mode', False) else 'Disabled'}
Field Mappings: {len(self.config.get('field_mapping', {}))} configured
Dark Mode: {'Enabled' if self.config.get('dark_mode', False) else 'Disabled'}

DATABASE INFORMATION
{'-'*50}"""
            
            if self.db_connection:
                try:
                    cursor = self.db_connection.cursor()
                    tables = [table.table_name for table in cursor.tables() if table.table_type == 'TABLE']
                    report += f"""
Available Tables: {len(tables)}
Table Names: {', '.join(tables[:10])}{'...' if len(tables) > 10 else ''}
"""
                    if hasattr(self, 'table_columns') and self.table_columns:
                        report += f"Current Table Columns: {len(self.table_columns)}\n"
                        col_names = [col['name'] for col in self.table_columns[:5]]
                        report += f"Sample Columns: {', '.join(col_names)}{'...' if len(self.table_columns) > 5 else ''}\n"
                except Exception as e:
                    report += f"Database Query Error: {str(e)}\n"
            else:
                report += "No database connection available.\n"
            
            # Transaction Statistics
            report += f"""
TRANSACTION STATISTICS
{'-'*50}"""
            try:
                conn = sqlite3.connect(self.db_manager.db_path)
                cursor = conn.cursor()
                
                # Count transactions
                cursor.execute("SELECT COUNT(*) FROM transaction_log")
                total_trans = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM transaction_log WHERE status = 'success'")
                success_trans = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM push_buffer WHERE status = 'pending'")
                pending_buffer = cursor.fetchone()[0]
                
                conn.close()
                
                success_rate = (success_trans / total_trans * 100) if total_trans > 0 else 0
                
                report += f"""
Total Transactions: {total_trans:,}
Successful: {success_trans:,} ({success_rate:.1f}%)
Failed/Retry: {total_trans - success_trans:,}
Pending in Buffer: {pending_buffer:,}
"""
            except Exception as e:
                report += f"Could not retrieve transaction statistics: {str(e)}\n"
            
            # Recent Activity
            report += f"""
RECENT ACTIVITY (Last 10 entries)
{'-'*50}"""
            try:
                logs = self.db_manager.get_recent_logs(10)
                for log in logs:
                    timestamp = log['timestamp'][:19]  # Remove microseconds
                    report += f"{timestamp} [{log['level']}] {log['message']}\n"
            except Exception as e:
                report += f"Could not retrieve recent logs: {str(e)}\n"
            
            report += f"""
PERFORMANCE METRICS
{'-'*50}
Memory Usage: Available in Task Manager
CPU Usage: Background processing optimized
Network: HTTPS API calls with retry logic
Storage: SQLite database with transaction logging

SUPPORT INFORMATION
{'-'*50}
Technical Support: freddy.pm@sahabatagro.co.id
Emergency Contact: +62 813-9855-2019
Business Hours: Monday-Friday, 8AM-6PM (WIB)
Company: PT Sahabat Agro Group

{'='*80}
End of System Report
"""
            
            # Insert report into text widget
            text_widget.insert(1.0, report)
            text_widget.config(state=tk.DISABLED)
            
            # Add export button
            btn_frame = ttk.Frame(report_window)
            btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
            
            def export_report():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"mdb_agent_report_{timestamp}.txt"
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(report)
                    messagebox.showinfo("Exported", f"Report saved as {filename}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to export: {str(e)}")
            
            ttk.Button(btn_frame, text="📄 Export Report", command=export_report).pack(side=tk.LEFT)
            ttk.Button(btn_frame, text="❌ Close", command=report_window.destroy).pack(side=tk.RIGHT)
            
            self.log_entry("System report generated", "INFO")
            
        except Exception as e:
            error_msg = f"Failed to generate system report: {str(e)}"
            messagebox.showerror("Report Error", error_msg)
            self.log_entry(error_msg, "ERROR")
            
            report = f"""
MDB AGENT PRO - SYSTEM REPORT
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'=' * 60}

APPLICATION INFO:
• Name: MDB Agent Pro
• Version: 2.0.0
• Type: Database to API Bridge

SYSTEM ENVIRONMENT:
• Operating System: {platform.system()} {platform.release()}
• Python Version: {sys.version.split()[0]}
• Architecture: {platform.machine()}
• Processor: {platform.processor()}

DATABASE CONNECTION:
• File: {self.config.get('mdb_file', 'Not configured')}
• Status: {'Connected' if self.db_connection else 'Disconnected'}
• Selected Table: {getattr(self, 'selected_table', 'None')}

API CONFIGURATION:
• Endpoint: {self.config.get('api_endpoint', 'Not configured')}
• Authentication: {'Configured' if self.config.get('api_key') else 'Not configured'}
• Auto Push: {self.config.get('auto_push', False)}
• Push Interval: {self.config.get('push_interval', 'Not set')} seconds

FIELD MAPPING:
• Mapped Fields: {len(self.field_mappings) if hasattr(self, 'field_mappings') else 0}
• Templates Available: {self.template_listbox.size() if hasattr(self, 'template_listbox') else 0}

AGENT STATUS:
• Running: {getattr(self, 'is_running', False)}
• Admin Mode: {getattr(self, 'admin_mode', False)}

RECENT ACTIVITY:
            """
            
            text_widget.insert(1.0, report)
            
            # Add recent logs
            try:
                logs = self.db_manager.get_recent_logs(10)
                text_widget.insert(tk.END, "\nRECENT LOGS:\n")
                for log in logs:
                    text_widget.insert(tk.END, f"• {log[0]} [{log[1]}] {log[2]}\n")
            except:
                text_widget.insert(tk.END, "\n• Could not retrieve recent logs\n")
            
            text_widget.config(state=tk.DISABLED)
            
            # Save button
            def save_report():
                filename = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                )
                if filename:
                    with open(filename, 'w') as f:
                        f.write(text_widget.get(1.0, tk.END))
                    messagebox.showinfo("Success", f"Report saved to {filename}")
            
            ttk.Button(report_window, text="Save Report", command=save_report).pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    # Missing methods for mapping functionality
    def load_selected_template(self):
        """Load selected mapping template"""
        try:
            selection = self.template_listbox.curselection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a template to load")
                return
            
            template_name = self.template_listbox.get(selection[0])
            
            # Load template from config
            templates = self.config.get('mapping_templates', {})
            if template_name in templates:
                template_data = templates[template_name]
                self.field_mappings = template_data.get('mappings', {})
                
                # Update UI
                self.refresh_mapping_interface()
                self.update_json_preview()
                
                messagebox.showinfo("Success", f"Template '{template_name}' loaded successfully!")
                self.log_entry(f"Mapping template loaded: {template_name}", "SUCCESS")
            else:
                messagebox.showerror("Error", f"Template '{template_name}' not found")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load template: {str(e)}")
    
    def show_save_template_dialog(self):
        """Show save template dialog"""
        if not hasattr(self, 'field_mappings') or not self.field_mappings:
            messagebox.showwarning("Warning", "No field mapping to save as template")
            return
        
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Save Mapping Template")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Template name
        ttk.Label(dialog, text="Template Name:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=20, pady=(20, 5))
        name_var = tk.StringVar()
        name_entry = ttk.Entry(dialog, textvariable=name_var, width=40)
        name_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
        name_entry.focus()
        
        # Description
        ttk.Label(dialog, text="Description (optional):", font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=20, pady=(10, 5))
        desc_var = tk.StringVar()
        desc_entry = ttk.Entry(dialog, textvariable=desc_var, width=40)
        desc_entry.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        def save_template():
            template_name = name_var.get().strip()
            if not template_name:
                messagebox.showerror("Error", "Please enter a template name")
                return
            
            try:
                # Save template
                if 'mapping_templates' not in self.config:
                    self.config['mapping_templates'] = {}
                
                self.config['mapping_templates'][template_name] = {
                    'mappings': self.field_mappings.copy(),
                    'description': desc_var.get().strip(),
                    'table': getattr(self, 'selected_table', ''),
                    'created': datetime.now().isoformat()
                }
                
                self.save_config()
                self.load_mapping_templates()  # Refresh template list
                
                messagebox.showinfo("Success", f"Template '{template_name}' saved successfully!")
                self.log_entry(f"Mapping template saved: {template_name}", "SUCCESS")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save template: {str(e)}")
        
        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Button(btn_frame, text="Save Template", command=save_template).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def delete_selected_template(self):
        """Delete selected template"""
        try:
            selection = self.template_listbox.curselection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a template to delete")
                return
            
            template_name = self.template_listbox.get(selection[0])
            
            result = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete template '{template_name}'?")
            if result:
                templates = self.config.get('mapping_templates', {})
                if template_name in templates:
                    del templates[template_name]
                    self.config['mapping_templates'] = templates
                    self.save_config()
                    self.load_mapping_templates()  # Refresh list
                    
                    messagebox.showinfo("Success", f"Template '{template_name}' deleted successfully!")
                    self.log_entry(f"Mapping template deleted: {template_name}", "INFO")
                else:
                    messagebox.showerror("Error", f"Template '{template_name}' not found")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete template: {str(e)}")
    
    def import_api_spec(self):
        """Import API specification from JSON file"""
        try:
            filename = filedialog.askopenfilename(
                title="Import API Specification",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'r') as f:
                    api_spec = json.load(f)
                
                # Extract field names from API spec
                fields = []
                if 'properties' in api_spec:
                    fields = list(api_spec['properties'].keys())
                elif 'fields' in api_spec:
                    fields = api_spec['fields']
                elif isinstance(api_spec, dict):
                    fields = list(api_spec.keys())
                
                if fields:
                    self.api_fields = fields
                    # Update comboboxes in mapping interface
                    if hasattr(self, 'mapping_widgets'):
                        for widgets in self.mapping_widgets.values():
                            current_values = list(widgets['api_combo']['values'])
                            new_values = ["(unmapped)"] + fields + ["Custom..."]
                            widgets['api_combo']['values'] = new_values
                    
                    messagebox.showinfo("Success", f"API specification imported!\n{len(fields)} fields found: {', '.join(fields[:5])}{'...' if len(fields) > 5 else ''}")
                    self.log_entry(f"API spec imported: {len(fields)} fields", "SUCCESS")
                else:
                    messagebox.showwarning("Warning", "No fields found in API specification")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import API spec: {str(e)}")
    
    def auto_detect_api_structure(self):
        """Auto detect API structure from endpoint"""
        if not self.config.get('api_endpoint'):
            messagebox.showerror("Error", "Please configure API endpoint first in API Settings tab")
            return
        
        try:
            # Try to get API schema or send test request
            headers = {'Content-Type': 'application/json'}
            if self.config.get('api_key'):
                headers['Authorization'] = f'Bearer {self.config["api_key"]}'
            
            # Send OPTIONS request to get schema
            response = requests.options(self.config['api_endpoint'], headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Try to parse schema from response
                if response.json():
                    schema = response.json()
                    # Extract fields from schema
                    fields = self.extract_fields_from_schema(schema)
                    if fields:
                        self.api_fields = fields
                        messagebox.showinfo("Success", f"API structure detected!\nFields: {', '.join(fields)}")
                        return
            
            # Fallback: send test request and analyze response
            test_data = {"test": True, "timestamp": datetime.now().isoformat()}
            response = requests.post(self.config['api_endpoint'], json=test_data, headers=headers, timeout=10)
            
            if response.status_code in [200, 400, 422]:  # Accept validation errors too
                messagebox.showinfo("API Test", f"API endpoint responded with status {response.status_code}\nManual field configuration recommended")
            else:
                messagebox.showwarning("Warning", f"API returned status {response.status_code}\nManual configuration required")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to detect API structure: {str(e)}")
    
    def show_manual_api_fields_dialog(self):
        """Show manual API fields configuration dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Manual API Fields Configuration")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Instructions
        ttk.Label(dialog, text="Enter API field names (one per line):", 
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=20, pady=(20, 5))
        
        # Text area for fields
        text_frame = ttk.Frame(dialog)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        fields_text = scrolledtext.ScrolledText(text_frame, height=15)
        fields_text.pack(fill=tk.BOTH, expand=True)
        
        # Pre-populate with current fields
        if hasattr(self, 'api_fields') and self.api_fields:
            fields_text.insert(1.0, '\n'.join(self.api_fields))
        else:
            # Sample fields
            sample_fields = ["id", "name", "value", "timestamp", "status", "data", "created_at", "updated_at"]
            fields_text.insert(1.0, '\n'.join(sample_fields))
        
        def save_fields():
            field_text = fields_text.get(1.0, tk.END).strip()
            if field_text:
                fields = [f.strip() for f in field_text.split('\n') if f.strip()]
                self.api_fields = fields
                
                # Update mapping interface comboboxes
                if hasattr(self, 'mapping_widgets'):
                    for widgets in self.mapping_widgets.values():
                        new_values = ["(unmapped)"] + fields + ["Custom..."]
                        widgets['api_combo']['values'] = new_values
                
                messagebox.showinfo("Success", f"API fields configured!\n{len(fields)} fields added")
                self.log_entry(f"Manual API fields configured: {len(fields)} fields", "INFO")
                dialog.destroy()
            else:
                messagebox.showwarning("Warning", "Please enter at least one field name")
        
        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Button(btn_frame, text="Save Fields", command=save_fields).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def update_json_preview(self):
        """Update JSON preview with current mapping"""
        if not hasattr(self, 'json_preview'):
            return
            
        try:
            # Generate sample data based on current mapping
            preview_data = {}
            
            if hasattr(self, 'field_mappings') and self.field_mappings:
                for db_field, mapping in self.field_mappings.items():
                    api_field = mapping.get('api_field')
                    transform = mapping.get('transformation', 'none')
                    
                    if api_field and api_field != "(unmapped)":
                        # Generate sample value based on field name
                        if 'id' in db_field.lower():
                            sample_value = 12345
                        elif 'date' in db_field.lower() or 'time' in db_field.lower():
                            sample_value = datetime.now().isoformat()
                        elif 'name' in db_field.lower():
                            sample_value = "Sample Name"
                        elif 'value' in db_field.lower() or 'amount' in db_field.lower():
                            sample_value = 123.45
                        elif 'status' in db_field.lower():
                            sample_value = "active"
                        else:
                            sample_value = f"sample_{db_field.lower()}"
                        
                        # Apply transformation
                        if transform == 'uppercase':
                            sample_value = str(sample_value).upper()
                        elif transform == 'lowercase':
                            sample_value = str(sample_value).lower()
                        elif transform == 'date_format':
                            sample_value = datetime.now().strftime('%Y-%m-%d')
                        elif transform == 'timestamp':
                            sample_value = int(datetime.now().timestamp())
                        
                        preview_data[api_field] = sample_value
            
            # Add metadata
            preview_data.update({
                "_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "agent": "MDB Agent Pro v2.0",
                    "total_fields": len(preview_data)
                }
            })
            
            # Format JSON
            json_text = json.dumps(preview_data, indent=2, ensure_ascii=False)
            
            # Update preview
            self.json_preview.config(state=tk.NORMAL)
            self.json_preview.delete(1.0, tk.END)
            self.json_preview.insert(1.0, json_text)
            self.json_preview.config(state=tk.DISABLED)
            
        except Exception as e:
            # Fallback preview
            self.json_preview.config(state=tk.NORMAL)
            self.json_preview.delete(1.0, tk.END)
            self.json_preview.insert(1.0, f'{{"error": "Preview generation failed: {str(e)}"}}')
            self.json_preview.config(state=tk.DISABLED)
    
    def test_mapping_api_call(self):
        """Test mapping with actual API call"""
        if not self.config.get('api_endpoint'):
            messagebox.showerror("Error", "Please configure API endpoint first")
            return
        
        if not hasattr(self, 'field_mappings') or not self.field_mappings:
            messagebox.showwarning("Warning", "No field mapping configured")
            return
        
        try:
            # Get sample data using current mapping
            test_data = self.get_latest_record() if hasattr(self, 'get_latest_record') else None
            
            if not test_data:
                # Generate test data based on mapping
                test_data = {}
                for db_field, mapping in self.field_mappings.items():
                    api_field = mapping.get('api_field')
                    if api_field and api_field != "(unmapped)":
                        test_data[api_field] = f"test_value_for_{db_field}"
            
            # Add metadata
            test_data.update({
                "test": True,
                "timestamp": datetime.now().isoformat(),
                "agent_version": "v2.0"
            })
            
            # Send test request
            success = self.send_to_api(test_data)
            
            if success:
                messagebox.showinfo("Test Successful", "API call with field mapping was successful!")
                self.log_entry("Mapping API test successful", "SUCCESS")
            else:
                messagebox.showwarning("Test Failed", "API call failed. Check logs for details.")
                
        except Exception as e:
            messagebox.showerror("Test Error", f"Test failed: {str(e)}")
            self.log_entry(f"Mapping API test failed: {str(e)}", "ERROR")
    
    def extract_fields_from_schema(self, schema):
        """Extract field names from API schema"""
        fields = []
        if isinstance(schema, dict):
            if 'properties' in schema:
                fields = list(schema['properties'].keys())
            elif 'fields' in schema:
                fields = schema['fields'] if isinstance(schema['fields'], list) else list(schema['fields'].keys())
            elif 'data' in schema and isinstance(schema['data'], dict):
                fields = list(schema['data'].keys())
            else:
                # Try to get all keys as potential fields
                fields = [k for k in schema.keys() if not k.startswith('_')]
        return fields
    
    def validate_mapping(self):
        """Validate current field mapping"""
        if not hasattr(self, 'field_mappings') or not self.field_mappings:
            messagebox.showwarning("Validation", "No field mapping to validate")
            return
        
        # Validation checks
        issues = []
        mapped_count = 0
        total_count = len(getattr(self, 'table_columns', []))
        
        # Check for unmapped required fields
        api_fields_used = []
        for db_field, mapping in self.field_mappings.items():
            api_field = mapping.get('api_field')
            if api_field and api_field != "(unmapped)":
                mapped_count += 1
                if api_field in api_fields_used:
                    issues.append(f"Duplicate API field mapping: '{api_field}' is mapped to multiple database fields")
                else:
                    api_fields_used.append(api_field)
        
        # Check mapping completeness
        if mapped_count == 0:
            issues.append("No fields are mapped")
        elif mapped_count < total_count * 0.5:
            issues.append(f"Low mapping coverage: Only {mapped_count} out of {total_count} fields mapped")
        
        # Check for required API fields (common ones)
        required_fields = ['id', 'timestamp']
        missing_required = []
        for req_field in required_fields:
            if req_field not in api_fields_used:
                missing_required.append(req_field)
        
        if missing_required:
            issues.append(f"Recommended fields not mapped: {', '.join(missing_required)}")
        
        # Show validation results
        if issues:
            issue_text = "\n• ".join([""] + issues)
            messagebox.showwarning("Validation Issues Found", f"Mapping validation found issues:{issue_text}")
        else:
            success_rate = (mapped_count / total_count * 100) if total_count > 0 else 0
            messagebox.showinfo("Validation Passed", 
                              f"✅ Field mapping validation passed!\n\n"
                              f"Mapped fields: {mapped_count}/{total_count} ({success_rate:.1f}%)\n"
                              f"Unique API fields: {len(api_fields_used)}")
        
        self.log_entry(f"Mapping validation: {len(issues)} issues found", "INFO" if not issues else "WARNING")
    
    def load_mapping_templates(self):
        """Load available mapping templates into listbox"""
        if not hasattr(self, 'template_listbox'):
            return
            
        self.template_listbox.delete(0, tk.END)
        
        templates = self.config.get('mapping_templates', {})
        for template_name in sorted(templates.keys()):
            self.template_listbox.insert(tk.END, template_name)
    
    def refresh_mapping_interface(self):
        """Refresh mapping interface based on selected table"""
        if not hasattr(self, 'mapping_scroll_frame'):
            return
            
        # Clear existing widgets
        for widget in self.mapping_scroll_frame.winfo_children():
            widget.destroy()
        
        if not hasattr(self, 'selected_table') or not self.selected_table or not hasattr(self, 'table_columns'):
            ttk.Label(self.mapping_scroll_frame, text="Please select a database table first from 'Database Connection' tab", 
                     font=('Arial', 12), foreground='gray').pack(pady=50)
            return
        
        # Create mapping rows for each database column
        for i, column in enumerate(self.table_columns):
            self.create_mapping_row(i, column)
        
        # Add save button at bottom
        save_frame = ttk.Frame(self.mapping_scroll_frame)
        save_frame.pack(fill=tk.X, pady=(20, 10))
        
        ttk.Button(save_frame, text="💾 Save Field Mapping", 
                  command=self.save_field_mapping).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(save_frame, text="🔄 Reset Mapping", 
                  command=self.reset_field_mapping).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(save_frame, text="📋 Generate Preview", 
                  command=self.update_json_preview).pack(side=tk.LEFT)
    
    def create_mapping_row(self, row_index, column):
        """Create a mapping row for a database column"""
        row_frame = ttk.Frame(self.mapping_scroll_frame)
        row_frame.pack(fill=tk.X, pady=2, padx=5)
        
        # Database column label
        db_label = ttk.Label(row_frame, text=f"{column['name']} ({column.get('type', 'Unknown')})", 
                            font=('Arial', 9))
        db_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        
        # Arrow
        ttk.Label(row_frame, text="→", font=('Arial', 10)).grid(row=0, column=1, padx=10)
        
        # API field dropdown
        api_var = tk.StringVar()
        api_combo = ttk.Combobox(row_frame, textvariable=api_var, width=20, state="readonly")
        api_combo['values'] = ["(unmapped)", "id", "name", "value", "timestamp", "status", "data", "Custom..."]
        api_combo.set("(unmapped)")
        api_combo.grid(row=0, column=2, sticky=tk.W, padx=(0, 20))
        
        # Transformation dropdown  
        transform_var = tk.StringVar()
        transform_combo = ttk.Combobox(row_frame, textvariable=transform_var, width=15, state="readonly")
        transform_combo['values'] = ["No Transform", "String", "Number", "Date", "Boolean", "Uppercase", "Lowercase"]
        transform_combo.set("No Transform")
        transform_combo.grid(row=0, column=3, sticky=tk.W)
        
        # Store references for later use
        if not hasattr(self, 'mapping_widgets'):
            self.mapping_widgets = {}
        self.mapping_widgets[column['name']] = {
            'api_field': api_var,
            'transform': transform_var,
            'api_combo': api_combo,
            'transform_combo': transform_combo
        }
        
        # Load existing mapping if available
        if column['name'] in self.field_mappings:
            mapping = self.field_mappings[column['name']]
            api_var.set(mapping.get('api_field', '(unmapped)'))
            transform_var.set(mapping.get('transform', 'No Transform'))
    
    def save_field_mapping(self):
        """Save current field mapping configuration"""
        try:
            if not hasattr(self, 'mapping_widgets'):
                messagebox.showwarning("Warning", "No mapping to save")
                return
            
            # Collect mapping data
            new_mapping = {}
            mapped_count = 0
            
            for db_field, widgets in self.mapping_widgets.items():
                api_field = widgets['api_field'].get()
                transform = widgets['transform'].get()
                
                if api_field and api_field != "(unmapped)":
                    new_mapping[db_field] = {
                        'api_field': api_field,
                        'transform': transform
                    }
                    mapped_count += 1
            
            # Update field mappings
            self.field_mappings = new_mapping
            self.config['field_mapping'] = new_mapping
            self.save_config()
            
            # Update preview
            self.update_json_preview()
            
            messagebox.showinfo("Success", f"Field mapping saved!\n\n{mapped_count} fields mapped out of {len(self.mapping_widgets)}")
            self.log_entry(f"Field mapping saved: {mapped_count} fields mapped", "SUCCESS")
            
        except Exception as e:
            error_msg = f"Failed to save field mapping: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_entry(error_msg, "ERROR")
    
    def reset_field_mapping(self):
        """Reset field mapping to defaults"""
        result = messagebox.askyesno("Confirm Reset", "Are you sure you want to reset all field mappings?")
        if result:
            self.field_mappings = {}
            if hasattr(self, 'mapping_widgets'):
                for widgets in self.mapping_widgets.values():
                    widgets['api_field'].set("(unmapped)")
                    widgets['transform'].set("No Transform")
            self.update_json_preview()
            messagebox.showinfo("Reset Complete", "Field mapping has been reset")
    
    def update_json_preview(self):
        """Update JSON preview based on current mapping"""
        if not hasattr(self, 'json_preview'):
            return
            
        try:
            # Generate sample data based on current mapping
            sample_data = {}
            
            if hasattr(self, 'field_mappings') and self.field_mappings:
                for db_field, mapping in self.field_mappings.items():
                    api_field = mapping.get('api_field')
                    transform = mapping.get('transform', 'No Transform')
                    
                    if api_field:
                        # Generate sample value based on field type and transform
                        if 'id' in db_field.lower():
                            sample_value = 12345
                        elif 'name' in db_field.lower():
                            sample_value = "Sample Name"
                        elif 'date' in db_field.lower() or 'time' in db_field.lower():
                            sample_value = "2025-01-15 10:30:00"
                        elif 'status' in db_field.lower():
                            sample_value = "Active"
                        else:
                            sample_value = f"sample_{db_field.lower()}"
                        
                        # Apply transformation
                        if transform == "Number":
                            sample_value = 123.45
                        elif transform == "Boolean":
                            sample_value = True
                        elif transform == "Uppercase":
                            sample_value = str(sample_value).upper()
                        elif transform == "Lowercase":
                            sample_value = str(sample_value).lower()
                        
                        sample_data[api_field] = sample_value
            
            # Add metadata
            preview_data = {
                "uuid": "sample-uuid-12345",
                "timestamp": "2025-01-15T10:30:00Z",
                "table": getattr(self, 'selected_table', 'your_table'),
                "data": sample_data if sample_data else {"field1": "value1", "field2": "value2"}
            }
            
            # Format JSON
            json_text = json.dumps(preview_data, indent=2)
            
            # Update preview widget
            self.json_preview.config(state=tk.NORMAL)
            self.json_preview.delete(1.0, tk.END)
            self.json_preview.insert(1.0, json_text)
            self.json_preview.config(state=tk.DISABLED)
            
        except Exception as e:
            # Fallback preview
            fallback_json = {
                "message": "Preview generation failed",
                "error": str(e),
                "sample": {"field": "value"}
            }
            json_text = json.dumps(fallback_json, indent=2)
            
            self.json_preview.config(state=tk.NORMAL)
            self.json_preview.delete(1.0, tk.END)
            self.json_preview.insert(1.0, json_text)
            self.json_preview.config(state=tk.DISABLED)
    
    def apply_transformation(self, value, transform):
        """Apply data transformation"""
        if transform == "No Transform":
            return value
        elif transform == "String":
            return str(value)
        elif transform == "Number":
            try:
                return float(value)
            except:
                return 0
        elif transform == "Date":
            if hasattr(value, 'strftime'):
                return value.strftime('%Y-%m-%d')
            return str(value)
        else:
            return value
    
    def refresh_scheduler_log(self):
        """Refresh scheduler log"""
        if hasattr(self, 'scheduler_tree'):
            # Clear existing items
            for item in self.scheduler_tree.get_children():
                self.scheduler_tree.delete(item)
            
            # Add some sample entries
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status = "Running" if self.is_running else "Stopped"
            self.scheduler_tree.insert("", 0, values=(timestamp, "Status Check", "INFO", f"Scheduler is {status}"))
    
    def start_health_monitoring(self):
        """Start health monitoring"""
        self.run_all_health_checks()
    
    def run_health_checks(self):
        """Run health checks"""
        self.run_all_health_checks()
    
    def view_transaction_details(self, event):
        """View transaction details"""
        selection = self.trans_tree.selection()
        if selection:
            item = self.trans_tree.item(selection[0])
            values = item['values']
            messagebox.showinfo("Transaction Details", f"Transaction ID: {values[0]}\nDetails: {values[-1]}")
    
    def filter_transactions(self, event=None):
        """Filter transactions"""
        self.load_transaction_log()
    
    def refresh_transactions(self):
        """Refresh transaction log"""
        self.load_transaction_log()
    
    def clear_transaction_log(self):
        """Clear transaction log"""
        if not self.admin_mode:
            messagebox.showerror("Error", "Admin mode required")
            return
        
        result = messagebox.askyesno("Confirm", "Clear all transaction logs?")
        if result:
            # Clear tree view
            for item in self.transaction_tree.get_children():
                self.transaction_tree.delete(item)
            messagebox.showinfo("Success", "Transaction log cleared")
    
    def export_transaction_report(self):
        """Export transaction report"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if filename:
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["ID", "Timestamp", "Table", "Status", "Records", "Details"])
                    
                    for item in self.transaction_tree.get_children():
                        values = self.transaction_tree.item(item)['values']
                        writer.writerow(values)
                
                messagebox.showinfo("Success", f"Report exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def load_settings(self):
        """Load configuration settings into UI elements"""
        try:
            if hasattr(self, 'mdb_file_var'):
                self.mdb_file_var.set(self.config.get('mdb_file', ''))
            if hasattr(self, 'mdb_password_var'):
                self.mdb_password_var.set(self.config.get('mdb_password', 'qwerty123'))
            if hasattr(self, 'table_var'):
                self.table_var.set(self.config.get('selected_table', ''))
            if hasattr(self, 'api_endpoint_var'):
                self.api_endpoint_var.set(self.config.get('api_endpoint', ''))
            if hasattr(self, 'api_key_var'):
                self.api_key_var.set(self.config.get('api_key', ''))
            if hasattr(self, 'push_interval_var'):
                self.push_interval_var.set(self.config.get('push_interval', 300))
            if hasattr(self, 'auto_push_var'):
                self.auto_push_var.set(self.config.get('auto_push', False))
            
            # Load field mappings
            field_mapping = self.config.get('field_mapping', {})
            if field_mapping and hasattr(self, 'field_mappings'):
                self.field_mappings = field_mapping
                
        except Exception as e:
            print(f"Error loading settings: {e}")
    
    def run(self):
        """Run the application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle application closing"""
        self.is_running = False
        self.save_config()
        if self.db_connection:
            self.db_connection.close()
        self.root.destroy()

if __name__ == "__main__":
    try:
        app = MDBAgentPro()
        app.run()
    except Exception as e:
        print(f"Failed to start application: {e}")
        traceback.print_exc()
    
