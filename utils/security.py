#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Manager Module
=======================
Handles encryption/decryption and authentication for MDB Agent Pro

This module consolidates all security-related functionality including:
- Configuration encryption/decryption
- Password management
- Authentication handling
- Secure salt generation

Author: Freddy Mazmur
Company: PT Sahabat Agro Group
"""

import base64
import hashlib
import os
import secrets
from typing import Optional

# Optional cryptography imports with fallback
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


class SecurityManager:
    """Enhanced security manager with proper salt generation and improved security"""
    
    def __init__(self, password: str = "default_password", salt_file: str = "salt.dat"):
        """
        Initialize security manager with dynamic salt generation
        
        Args:
            password: Encryption password
            salt_file: File to store/load salt from
        """
        self.password = password.encode()
        self.salt_file = salt_file
        self.salt = self._get_or_create_salt()
        
        if CRYPTOGRAPHY_AVAILABLE:
            self._setup_encryption()
        else:
            print("Warning: Cryptography library not available. Using basic encoding.")
    
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create a new random one"""
        if os.path.exists(self.salt_file):
            try:
                with open(self.salt_file, 'rb') as f:
                    return f.read()
            except Exception:
                pass
        
        # Generate new random salt
        salt = secrets.token_bytes(32)
        try:
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
        except Exception:
            # Fallback to fixed salt if file writing fails
            salt = b'fallback_salt_1234567890123456'
        
        return salt
    
    def _setup_encryption(self):
        """Setup Fernet encryption with proper salt"""
        if not CRYPTOGRAPHY_AVAILABLE:
            return
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        self.cipher = Fernet(key)
    
    def encrypt(self, data: str) -> str:
        """
        Encrypt string data
        
        Args:
            data: Plain text to encrypt
            
        Returns:
            Encrypted string
        """
        if CRYPTOGRAPHY_AVAILABLE and hasattr(self, 'cipher'):
            return self.cipher.encrypt(data.encode()).decode()
        else:
            return base64.b64encode(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt string data
        
        Args:
            encrypted_data: Encrypted data to decrypt
            
        Returns:
            Decrypted plain text
        """
        try:
            if CRYPTOGRAPHY_AVAILABLE and hasattr(self, 'cipher'):
                return self.cipher.decrypt(encrypted_data.encode()).decode()
            else:
                return base64.b64decode(encrypted_data.encode()).decode()
        except Exception:
            return encrypted_data  # Return as-is if decryption fails
    
    def hash_password(self, password: str) -> str:
        """
        Create a secure hash of a password
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password
        """
        return hashlib.pbkdf2_hmac('sha256', password.encode(), self.salt, 100000).hex()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            password: Plain text password to verify
            hashed: Stored hash to compare against
            
        Returns:
            True if password matches, False otherwise
        """
        return self.hash_password(password) == hashed
    
    def generate_api_key(self, length: int = 32) -> str:
        """
        Generate a secure random API key
        
        Args:
            length: Length of the API key
            
        Returns:
            Random API key string
        """
        return secrets.token_urlsafe(length)


class AuthenticationManager:
    """Manage authentication states and PIN verification"""
    
    def __init__(self, security_manager: SecurityManager):
        self.security = security_manager
        self.admin_sessions = {}  # Track admin sessions
    
    def verify_admin_pin(self, pin: str, stored_pin_hash: str) -> bool:
        """
        Verify admin PIN against stored hash
        
        Args:
            pin: PIN to verify
            stored_pin_hash: Stored hashed PIN
            
        Returns:
            True if PIN is correct
        """
        return self.security.verify_password(pin, stored_pin_hash)
    
    def create_admin_session(self, session_id: str) -> None:
        """Create an admin session with expiry"""
        from datetime import datetime, timedelta
        self.admin_sessions[session_id] = {
            'created': datetime.now(),
            'expires': datetime.now() + timedelta(hours=1)  # 1 hour session
        }
    
    def is_admin_session_valid(self, session_id: str) -> bool:
        """Check if admin session is still valid"""
        from datetime import datetime
        if session_id not in self.admin_sessions:
            return False
        
        session = self.admin_sessions[session_id]
        if datetime.now() > session['expires']:
            del self.admin_sessions[session_id]
            return False
        
        return True
    
    def cleanup_expired_sessions(self) -> None:
        """Remove expired admin sessions"""
        from datetime import datetime
        expired_sessions = [
            sid for sid, session in self.admin_sessions.items()
            if datetime.now() > session['expires']
        ]
        for sid in expired_sessions:
            del self.admin_sessions[sid]
