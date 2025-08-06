#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI Utilities Module
===================
Reusable GUI components and utilities for MDB Agent Pro

This module provides:
- Status indicator widgets
- Navigation components
- Common GUI patterns
- Style management

Author: Freddy Mazmur
Company: PT Sahabat Agro Group
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Tuple, Callable, Optional, Union


class StatusIndicator:
    """Enhanced status indicator widget with more states and animations"""
    
    STATUS_COLORS = {
        "good": "#4CAF50",      # Green
        "warning": "#FF9800",   # Orange
        "error": "#F44336",     # Red
        "unknown": "#9E9E9E",   # Gray
        "connecting": "#2196F3", # Blue
        "disabled": "#BDBDBD"   # Light Gray
    }
    
    def __init__(self, parent, label: str, size: int = 20):
        """
        Initialize status indicator
        
        Args:
            parent: Parent widget
            label: Label text
            size: Size of the indicator circle
        """
        self.frame = ttk.Frame(parent)
        self.label = label
        self.status = "unknown"
        self.size = size
        
        # Create canvas for colored circle
        self.canvas = tk.Canvas(
            self.frame, 
            width=size, 
            height=size, 
            highlightthickness=0
        )
        self.canvas.pack(side=tk.LEFT, padx=(0, 5))
        
        # Label
        self.label_widget = ttk.Label(self.frame, text=label)
        self.label_widget.pack(side=tk.LEFT)
        
        self.update_status("unknown")
    
    def update_status(self, status: str, tooltip: str = ""):
        """
        Update status and color
        
        Args:
            status: Status key
            tooltip: Optional tooltip text
        """
        self.status = status
        self.canvas.delete("all")
        
        color = self.STATUS_COLORS.get(status, self.STATUS_COLORS["unknown"])
        
        # Draw circle with border for better visibility
        self.canvas.create_oval(
            2, 2, self.size-2, self.size-2, 
            fill=color, 
            outline="#333333", 
            width=1
        )
        
        # Add tooltip if provided
        if tooltip:
            self._create_tooltip(tooltip)
    
    def _create_tooltip(self, text: str):
        """Create tooltip for the status indicator"""
        def show_tooltip(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            
            label = tk.Label(
                tooltip, 
                text=text, 
                background="#ffffe0", 
                border=1, 
                font=("Arial", 9)
            )
            label.pack()
            
            # Auto-hide after 3 seconds
            tooltip.after(3000, tooltip.destroy)
        
        def hide_tooltip(event):
            pass
        
        self.canvas.bind("<Enter>", show_tooltip)
        self.canvas.bind("<Leave>", hide_tooltip)


class NavigationManager:
    """Manages navigation sections and buttons with consistent styling"""
    
    def __init__(self, parent_frame):
        """
        Initialize navigation manager
        
        Args:
            parent_frame: Parent frame for navigation
        """
        self.parent_frame = parent_frame
        self.nav_buttons: Dict[str, ttk.Button] = {}
        self.current_tab = None
        self.tab_callbacks: Dict[str, Callable] = {}
        self.main_switch_callback = None
    
    def create_section(self, title: str, buttons: List[Tuple[str, str]], 
                      is_first: bool = False) -> None:
        """
        Create a navigation section with consistent styling
        
        Args:
            title: Section title
            buttons: List of (text, tab_id) tuples
            is_first: Whether this is the first section (different padding)
        """
        # Section spacing
        top_padding = 5 if is_first else 15
        
        # Section header
        header = ttk.Label(
            self.parent_frame, 
            text=title, 
            font=('Arial', 9, 'bold'), 
            foreground='gray'
        )
        header.pack(anchor=tk.W, padx=5, pady=(top_padding, 5))
        
        # Section buttons
        for text, tab_id in buttons:
            btn = ttk.Button(
                self.parent_frame, 
                text=f"  {text}", 
                command=lambda t=tab_id: self.switch_tab(t),
                width=28
            )
            btn.pack(fill=tk.X, pady=1, padx=5)
            self.nav_buttons[tab_id] = btn
    
    def switch_tab(self, tab_id: str) -> None:
        """
        Switch to specified tab
        
        Args:
            tab_id: Tab identifier
        """
        # Update button styles
        for btn_id, btn in self.nav_buttons.items():
            if btn_id == tab_id:
                btn.configure(style='Selected.TButton')
            else:
                btn.configure(style='TButton')
        
        self.current_tab = tab_id
        
        # Call main switch callback (to handle actual tab switching)
        if self.main_switch_callback:
            self.main_switch_callback(tab_id)
        
        # Call registered callback if exists (for additional actions)
        if tab_id in self.tab_callbacks:
            self.tab_callbacks[tab_id]()
    
    def set_main_switch_callback(self, callback: Callable) -> None:
        """
        Set the main callback for tab switching
        
        Args:
            callback: Function to call for actual tab switching
        """
        self.main_switch_callback = callback
    
    def register_tab_callback(self, tab_id: str, callback: Callable) -> None:
        """
        Register callback for tab switching
        
        Args:
            tab_id: Tab identifier
            callback: Function to call when tab is switched to
        """
        self.tab_callbacks[tab_id] = callback
    
    def get_current_tab(self) -> Optional[str]:
        """Get current active tab"""
        return self.current_tab


class FieldMapper:
    """Enhanced field mapping engine for flat and nested JSON structures"""
    
    def __init__(self, field_mappings: Dict, mapping_mode: str = "flat"):
        """
        Initialize field mapper
        
        Args:
            field_mappings: Dictionary of {db_field: {api_field, transform, group}}
            mapping_mode: "flat", "nested", or "tbs_auto"
        """
        self.field_mappings = field_mappings or {}
        self.mapping_mode = mapping_mode
    
    def build_api_payload(self, raw_data: Union[Dict, List[Dict]]) -> Dict:
        """
        Build API payload from raw database data using field mappings
        
        Args:
            raw_data: Raw data from database (single record or list for batch)
            
        Returns:
            Mapped data ready for API
        """
        # Handle batch processing for multiple records
        if isinstance(raw_data, list):
            return self._build_batch_payload(raw_data)
        
        # Single record processing
        if self.mapping_mode == "flat":
            return self._build_flat_payload(raw_data)
        elif self.mapping_mode == "nested":
            return self._build_nested_payload(raw_data)
        elif self.mapping_mode == "tbs_auto":
            return self._build_tbs_payload(raw_data)
        else:
            return self._build_flat_payload(raw_data)
    
    def _build_batch_payload(self, raw_data_list: List[Dict]) -> Dict:
        """Build batch payload for multiple records (especially for TBS)"""
        if not raw_data_list:
            return {}
        
        # For TBS batch processing
        if self.mapping_mode == "tbs_auto":
            order_data_items = []
            header_fields = {}
            
            for raw_data in raw_data_list:
                order_data_item = {
                    'partner_id': 1,
                    'journal_id': 1,
                    'date_order': '2025-01-15',
                    'order_line': []
                }
                order_line_item = {}
                
                for db_field, mapping in self.field_mappings.items():
                    api_field = mapping.get('api_field')
                    if not api_field or db_field not in raw_data:
                        continue
                        
                    value = raw_data[db_field]
                    if value is None:
                        continue
                        
                    transformed_value = self._apply_transform(value, mapping.get('transform', 'No Transform'))
                    
                    if api_field in ['external_id', 'uuid', 'timestamp', 'source']:
                        # Header fields only from first record
                        if not header_fields:
                            header_fields[api_field] = transformed_value
                    elif api_field.startswith('order_data.order_line.'):
                        field_name = api_field.split('.', 2)[2]
                        order_line_item[field_name] = transformed_value
                    elif api_field.startswith('order_data.'):
                        field_name = api_field.split('.', 1)[1]
                        if field_name != 'order_line':
                            order_data_item[field_name] = transformed_value
                    else:
                        order_data_item[api_field] = transformed_value
                
                # Add order_line if we have line data
                if order_line_item:
                    order_data_item['order_line'] = [order_line_item]
                
                order_data_items.append(order_data_item)
            
            # Build JSON-RPC batch structure
            result = {
                "jsonrpc": "2.0",
                "params": {
                    "order_data": order_data_items  # Array of multiple order_data items
                }
            }
            
            # Add header fields
            for key, value in header_fields.items():
                result["params"][key] = value
            
            return result
        
        # For other modes, process first record only
        return self.build_api_payload(raw_data_list[0])
    
    def _build_flat_payload(self, raw_data: Dict) -> Dict:
        """Build flat JSON structure"""
        result = {}
        
        for db_field, mapping in self.field_mappings.items():
            api_field = mapping.get('api_field')
            if not api_field or db_field not in raw_data:
                continue
                
            value = raw_data[db_field]
            if value is not None:
                transformed_value = self._apply_transform(value, mapping.get('transform', 'No Transform'))
                result[api_field] = transformed_value
        
        return result
    
    def _build_nested_payload(self, raw_data: Dict) -> Dict:
        """Build nested JSON structure with order_line arrays or order_data structure"""
        header_data = {}
        order_lines = []
        order_data = []
        groups = {}
        
        for db_field, mapping in self.field_mappings.items():
            api_field = mapping.get('api_field')
            group = mapping.get('group')
            
            if not api_field or db_field not in raw_data:
                continue
                
            value = raw_data[db_field]
            if value is None:
                continue
                
            transformed_value = self._apply_transform(value, mapping.get('transform', 'No Transform'))
            
            # Handle order_data structure (TBS specific)
            if api_field.startswith('order_data.'):
                field_name = api_field.split('.', 1)[1]
                if not order_data:
                    order_data.append({
                        'partner_id': None,
                        'journal_id': None,
                        'date_order': None,
                        'order_line': []
                    })
                
                if field_name.startswith('order_line.'):
                    # Nested order_line within order_data
                    line_field = field_name.split('.', 1)[1]
                    if not order_data[0]['order_line']:
                        order_data[0]['order_line'] = [{}]
                    order_data[0]['order_line'][0][line_field] = transformed_value
                else:
                    # Direct order_data field
                    order_data[0][field_name] = transformed_value
                    
            # Handle regular order_line structure
            elif api_field.startswith('order_line.'):
                field_name = api_field.split(".", 1)[1]
                if not order_lines:
                    order_lines.append({})
                order_lines[0][field_name] = transformed_value
                
            # Handle grouped fields (arrays/nested objects)
            elif group and group != 'header':
                if group not in groups:
                    groups[group] = {}
                
                # Extract field name (remove group prefix if exists)
                if api_field.startswith(f"{group}."):
                    field_name = api_field.split(".", 1)[1]
                else:
                    field_name = api_field
                    
                groups[group][field_name] = transformed_value
            else:
                # Regular header field
                header_data[api_field] = transformed_value
        
        # Build result
        result = header_data.copy()
        
        # Add order_data if present (TBS structure)
        if order_data:
            # Ensure required fields have defaults
            for item in order_data:
                if item.get('partner_id') is None:
                    item['partner_id'] = 1
                if item.get('journal_id') is None:
                    item['journal_id'] = 1
                if item.get('date_order') is None:
                    item['date_order'] = '2025-01-15'
            result['order_data'] = order_data
            
        # Add regular order_line if present and no order_data
        elif order_lines:
            result['order_line'] = order_lines
        
        # Add other groups
        for group_name, group_data in groups.items():
            if group_name not in ['order_line', 'order_data']:
                result[group_name] = group_data
        
        return result
    
    def _build_tbs_payload(self, raw_data: Dict) -> Dict:
        """Build TBS (Timbangan Basah Segar) specific payload structure with JSON-RPC format"""
        # TBS structure dengan JSON-RPC format dan order_data sebagai array
        order_data_item = {
            'partner_id': 1,  # Default required values
            'journal_id': 1,
            'date_order': '2025-01-15',
            'order_line': []
        }
        header_fields = {}
        order_line_item = {}
        
        for db_field, mapping in self.field_mappings.items():
            api_field = mapping.get('api_field')
            if not api_field or db_field not in raw_data:
                continue
                
            value = raw_data[db_field]
            if value is None:
                continue
                
            transformed_value = self._apply_transform(value, mapping.get('transform', 'No Transform'))
            
            # Parse field path and assign to correct location
            if api_field in ['external_id', 'uuid', 'timestamp', 'source']:
                # These stay at root level
                header_fields[api_field] = transformed_value
            elif api_field.startswith('order_data.order_line.'):
                # Extract field name from order_data.order_line.field_name
                field_name = api_field.split('.', 2)[2]  # get field_name part
                order_line_item[field_name] = transformed_value
            elif api_field.startswith('order_data.'):
                # Extract field name from order_data.field_name
                field_name = api_field.split('.', 1)[1]  # get field_name part
                if field_name != 'order_line':  # Skip order_line prefix
                    order_data_item[field_name] = transformed_value
            else:
                # Fallback - put at order_data level
                order_data_item[api_field] = transformed_value
        
        # Add order_line item if we have any line data
        if order_line_item:
            order_data_item['order_line'] = [order_line_item]
        
        # Build final TBS structure with JSON-RPC format
        result = {
            "jsonrpc": "2.0",
            "params": {
                "order_data": [order_data_item]  # Array of order_data items
            }
        }
        
        # Add any header fields to params level
        for key, value in header_fields.items():
            result["params"][key] = value
        
        return result
    
    def _apply_transform(self, value, transform: str):
        """Apply data transformation to value"""
        if transform == "No Transform" or not transform:
            return value
        elif transform == "Number":
            try:
                return float(value) if '.' in str(value) else int(value)
            except (ValueError, TypeError):
                return 0
        elif transform == "Boolean":
            if isinstance(value, bool):
                return value
            return str(value).lower() in ('true', '1', 'yes', 'on', 'active')
        elif transform == "Uppercase":
            return str(value).upper()
        elif transform == "Lowercase":
            return str(value).lower()
        elif transform == "Date":
            # Keep as string for now, could add date formatting later
            return str(value)
        else:
            return value
    
    def validate_mapping(self) -> List[str]:
        """Validate current mapping configuration"""
        errors = []
        
        if not self.field_mappings:
            errors.append("No field mappings configured")
            return errors
        
        api_fields = []
        for db_field, mapping in self.field_mappings.items():
            api_field = mapping.get('api_field')
            if api_field:
                if api_field in api_fields:
                    errors.append(f"Duplicate API field: {api_field}")
                api_fields.append(api_field)
        
        # Mode-specific validation
        if self.mapping_mode == "tbs_auto":
            required_fields = ["external_id", "partner_id", "date_order"]
            for field in required_fields:
                if field not in api_fields:
                    errors.append(f"TBS mode requires field: {field}")
        
        return errors


class ConfigurationManager:
    """Centralized configuration management with validation"""
    
    def __init__(self, security_manager, default_config: Dict = None):
        """
        Initialize configuration manager
        
        Args:
            security_manager: SecurityManager instance
            default_config: Default configuration values
        """
        self.security = security_manager
        self.config_file = "config.encrypted"
        self.default_config = default_config or self._get_default_config()
        self.config = self.load_config()
        self.change_callbacks: List[Callable] = []
    
    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            "mdb_file": "",
            "mdb_password": "",
            "selected_table": "",
            "table_columns": [],
            "field_mapping": {},
            "api_endpoint": "",
            "api_key": "",
            "login_username": "",
            "login_password": "",
            "login_database": "",
            "push_interval": 300,
            "auto_push": False,
            "test_mode": False,
            "last_status": "Ready",
            "admin_pin_hash": "",  # Store hashed PIN
            "email_settings": {
                "smtp_server": "",
                "smtp_port": 587,
                "email": "",
                "password": "",
                "it_email": ""
            },
            "retry_settings": {
                "max_retries": 3,
                "retry_delay": 30,
                "exponential_backoff": True
            },
            "ui_settings": {
                "theme": "green",
                "auto_refresh": True,
                "log_level": "INFO"
            }
        }
    
    def load_config(self) -> Dict:
        """Load encrypted configuration with validation"""
        import os
        import json
        
        config = self.default_config.copy()
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    encrypted_data = f.read()
                decrypted_data = self.security.decrypt(encrypted_data)
                if decrypted_data:
                    loaded_config = json.loads(decrypted_data)
                    config.update(loaded_config)
            except Exception as e:
                print(f"Error loading config: {str(e)}")
        
        # Validate and fix any missing keys
        config = self._validate_config(config)
        return config
    
    def _validate_config(self, config: Dict) -> Dict:
        """Validate configuration and add missing keys"""
        def merge_dict(default: Dict, loaded: Dict) -> Dict:
            """Recursively merge dictionaries"""
            result = default.copy()
            for key, value in loaded.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = merge_dict(result[key], value)
                else:
                    result[key] = value
            return result
        
        return merge_dict(self.default_config, config)
    
    def save_config(self) -> bool:
        """Save encrypted configuration"""
        import json
        
        try:
            config_json = json.dumps(self.config, indent=2)
            encrypted_data = self.security.encrypt(config_json)
            
            with open(self.config_file, 'w') as f:
                f.write(encrypted_data)
            
            # Notify callbacks of configuration change
            for callback in self.change_callbacks:
                callback(self.config)
            
            return True
        except Exception as e:
            print(f"Error saving config: {str(e)}")
            return False
    
    def get(self, key: str, default=None):
        """Get configuration value with dot notation support"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value, auto_save: bool = True):
        """Set configuration value with dot notation support"""
        keys = key.split('.')
        config_ref = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config_ref:
                config_ref[k] = {}
            config_ref = config_ref[k]
        
        # Set the value
        config_ref[keys[-1]] = value
        
        if auto_save:
            self.save_config()
    
    def register_change_callback(self, callback: Callable):
        """Register callback for configuration changes"""
        self.change_callbacks.append(callback)
    
    def get_section(self, section: str) -> Dict:
        """Get entire configuration section"""
        return self.config.get(section, {})
    
    def update_section(self, section: str, updates: Dict, auto_save: bool = True):
        """Update configuration section"""
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section].update(updates)
        
        if auto_save:
            self.save_config()


class StyleManager:
    """Manages TTK styles and themes"""
    
    def __init__(self, style: ttk.Style):
        """
        Initialize style manager
        
        Args:
            style: TTK Style instance
        """
        self.style = style
        self.current_theme = "green"
        
    def setup_green_theme(self):
        """Setup the green theme"""
        # Configure the overall theme
        self.style.theme_use('clam')  # Base theme
        
        # Color scheme
        colors = {
            'primary': '#4CAF50',     # Green
            'primary_dark': '#388E3C',
            'primary_light': '#C8E6C9',
            'secondary': '#81C784',
            'background': '#F1F8E9',
            'surface': '#FFFFFF',
            'text': '#1B5E20',
            'text_secondary': '#4E4E4E'
        }
        
        # Configure styles
        self.style.configure('TButton', 
                           background=colors['primary'],
                           foreground='white',
                           borderwidth=1,
                           focuscolor='none')
        
        self.style.map('TButton',
                      background=[('active', colors['primary_dark']),
                                ('pressed', colors['primary_dark'])])
        
        self.style.configure('Selected.TButton',
                           background=colors['primary_dark'],
                           foreground='white')
        
        self.style.configure('TFrame',
                           background=colors['background'])
        
        self.style.configure('TLabel',
                           background=colors['background'],
                           foreground=colors['text'])
        
        self.style.configure('TEntry',
                           borderwidth=1,
                           relief='solid')
        
        # Custom styles
        self.style.configure('Sidebar.TFrame', 
                           background=colors['primary_light'])
        self.style.configure('Content.TFrame', 
                           background=colors['surface'])
        self.style.configure('Status.TFrame', 
                           background=colors['primary_light'])
        self.style.configure('Title.TLabel', 
                           font=('Arial', 12, 'bold'), 
                           foreground=colors['text'])
        self.style.configure('Header.TLabel', 
                           font=('Arial', 10, 'bold'), 
                           foreground=colors['text'])
    
    def setup_dark_theme(self):
        """Setup dark theme (future enhancement)"""
        # Could be implemented for user preference
        pass
    
    def apply_theme(self, theme_name: str):
        """Apply specified theme"""
        if theme_name == "green":
            self.setup_green_theme()
        elif theme_name == "dark":
            self.setup_dark_theme()
        
        self.current_theme = theme_name


class ErrorHandler:
    """Centralized error handling and user notification"""
    
    def __init__(self, log_manager, parent_window=None):
        """
        Initialize error handler
        
        Args:
            log_manager: LogManager instance
            parent_window: Parent window for dialogs
        """
        self.log_manager = log_manager
        self.parent = parent_window
    
    def handle_error(self, error: Exception, context: str = "", 
                    show_user: bool = True, level: str = "ERROR") -> None:
        """
        Handle error with logging and optional user notification
        
        Args:
            error: Exception object
            context: Context where error occurred
            show_user: Whether to show error to user
            level: Log level
        """
        import traceback
        from tkinter import messagebox
        
        error_msg = f"{context}: {str(error)}" if context else str(error)
        error_details = traceback.format_exc()
        
        # Log the error
        self.log_manager.log(level, error_msg, error_details)
        
        # Show to user if requested
        if show_user and self.parent:
            messagebox.showerror("Error", error_msg)
    
    def handle_warning(self, message: str, details: str = "", 
                      show_user: bool = False) -> None:
        """Handle warning messages"""
        from tkinter import messagebox
        
        self.log_manager.log("WARNING", message, details)
        
        if show_user and self.parent:
            messagebox.showwarning("Warning", message)
    
    def handle_info(self, message: str, details: str = "", 
                   show_user: bool = False) -> None:
        """Handle info messages"""
        from tkinter import messagebox
        
        self.log_manager.log("INFO", message, details)
        
        if show_user and self.parent:
            messagebox.showinfo("Information", message)
