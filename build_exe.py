#!/usr/bin/env python3
"""
Build Script untuk MDB Agent Pro v2.0
Membuat executable (.exe) untuk distribusi

Author: Freddy Mazmur
Company: PT Sahabat Agro Group
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_pyinstaller():
    """Check if PyInstaller is installed"""
    try:
        import PyInstaller
        print("✓ PyInstaller sudah terinstall")
        return True
    except ImportError:
        print("⚠ PyInstaller belum terinstall")
        return False

def install_pyinstaller():
    """Install PyInstaller"""
    print("📦 Installing PyInstaller...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("✓ PyInstaller berhasil diinstall")
        return True
    except subprocess.CalledProcessError:
        print("❌ Gagal install PyInstaller")
        return False

def clean_build_dirs():
    """Clean build directories"""
    dirs_to_clean = ['build', 'dist', '__pycache__']
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"🧹 Cleaned {dir_name}")

def create_spec_file():
    """Create PyInstaller spec file with custom configuration"""
    spec_content = '''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['mdb_agent_pro.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config.example.json', '.'),
        ('logo-PTSAG.png', '.'),
        ('README.md', '.'),
    ],
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'pyodbc',
        'requests',
        'cryptography',
        'sqlite3',
        'json',
        'threading',
        'datetime',
        'uuid',
        'base64',
        'hashlib',
        'os',
        'sys',
        'logging',
        'time',
        'platform',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='MDBAgentPro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version_file=None,
)
'''
    
    with open('MDBAgentPro.spec', 'w') as f:
        f.write(spec_content)
    print("✓ Spec file created: MDBAgentPro.spec")

def build_executable():
    """Build the executable using PyInstaller"""
    print("🔨 Building executable...")
    
    try:
        # Build using spec file
        cmd = [sys.executable, "-m", "PyInstaller", "--clean", "MDBAgentPro.spec"]
        subprocess.check_call(cmd)
        print("✓ Build completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        return False

def create_release_package():
    """Create release package with all necessary files"""
    if not os.path.exists('dist/MDBAgentPro.exe'):
        print("❌ Executable not found!")
        return False
    
    # Create release directory
    release_dir = 'release'
    if os.path.exists(release_dir):
        shutil.rmtree(release_dir)
    os.makedirs(release_dir)
    
    # Copy executable
    shutil.copy2('dist/MDBAgentPro.exe', release_dir)
    
    # Copy essential files
    files_to_copy = [
        'config.example.json',
        'requirements.txt', 
        'README.md',
        'logo-PTSAG.png'
    ]
    
    for file in files_to_copy:
        if os.path.exists(file):
            shutil.copy2(file, release_dir)
    
    # Create installation guide
    install_guide = '''# MDB Agent Pro v2.0 - Installation Guide

## Quick Start (Portable)

1. **Extract files** ke folder pilihan Anda
2. **Double-click** MDBAgentPro.exe untuk menjalankan
3. **Copy** config.example.json menjadi config.json dan edit sesuai kebutuhan

## System Requirements

- Windows 7/8/8.1/10/11 (32-bit or 64-bit)
- Microsoft Access Database Engine (for .mdb/.accdb support)

## First Time Setup

1. Jalankan MDBAgentPro.exe
2. Buka tab "Database Connection"
3. Browse dan pilih file database .mdb/.accdb Anda
4. Konfigurasi API settings di tab "API Settings"
5. Setup field mapping di tab "API Field Mapping"

## Files Description

- **MDBAgentPro.exe** - Main application (portable)
- **config.example.json** - Configuration template
- **README.md** - Complete documentation
- **logo-PTSAG.png** - Company logo

## Support

- Email: freddy.pm@sahabatagro.co.id
- Phone: +62 813-9855-2019
- Company: PT Sahabat Agro Group

---
© 2025 PT Sahabat Agro Group. All rights reserved.
'''
    
    with open(os.path.join(release_dir, 'INSTALL.md'), 'w') as f:
        f.write(install_guide)
    
    print(f"✓ Release package created in '{release_dir}' directory")
    print(f"📁 Files included:")
    for file in os.listdir(release_dir):
        size = os.path.getsize(os.path.join(release_dir, file))
        size_mb = size / (1024 * 1024)
        print(f"   - {file} ({size_mb:.1f} MB)")
    
    return True

def main():
    """Main build process"""
    print("🚀 MDB Agent Pro v2.0 - Build Script")
    print("=" * 50)
    
    # Check and install PyInstaller if needed
    if not check_pyinstaller():
        if not install_pyinstaller():
            print("❌ Cannot proceed without PyInstaller")
            return False
    
    # Clean previous builds
    clean_build_dirs()
    
    # Create spec file
    create_spec_file()
    
    # Build executable
    if not build_executable():
        return False
    
    # Create release package
    if not create_release_package():
        return False
    
    print("\n🎉 Build completed successfully!")
    print("\n📦 Release package ready:")
    print("   - Folder: release/")
    print("   - Executable: release/MDBAgentPro.exe")
    print("   - Ready for distribution!")
    
    print("\n💡 Usage:")
    print("   1. Copy 'release' folder to target PC")
    print("   2. Double-click MDBAgentPro.exe")
    print("   3. No Python installation required!")
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        print("\n❌ Build failed!")
        sys.exit(1)
    
    print("\n✅ Build successful!")
    input("\nPress Enter to exit...")
