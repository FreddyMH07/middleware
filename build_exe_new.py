#!/usr/bin/env python3
"""
MDB Agent Pro v2.0 - Build Script
Professional Database-to-API Bridge

Author: Freddy Mazmur
Company: PT Sahabat Agro Group
Email: freddy.pm@sahabatagro.co.id
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def clean_build_directories():
    """Clean previous build directories"""
    dirs_to_clean = ['build', 'dist', '__pycache__']
    
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            print(f"🗑️ Cleaning {dir_name}...")
            shutil.rmtree(dir_name, ignore_errors=True)
    
    print("✅ Build directories cleaned")

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        'pyinstaller',
        'tkinter',
        'pyodbc', 
        'requests',
        'cryptography'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'tkinter':
                import tkinter
            elif package == 'pyinstaller':
                import PyInstaller
            elif package == 'pyodbc':
                import pyodbc
            elif package == 'requests':
                import requests
            elif package == 'cryptography':
                import cryptography
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Install with: pip install -r requirements.txt")
        return False
    
    print("✅ All dependencies available")
    return True

def build_executable():
    """Build executable using PyInstaller"""
    print("🔨 Building MDB Agent Pro executable...")
    
    # PyInstaller command with optimized settings
    cmd = [
        'pyinstaller',
        '--name=MDBAgentPro',
        '--onefile',
        '--windowed',
        '--icon=logo-PTSAG.png',
        '--add-data=logo-PTSAG.png;.',
        '--add-data=config.example.json;.',
        '--hidden-import=tkinter',
        '--hidden-import=tkinter.ttk',
        '--hidden-import=pyodbc',
        '--hidden-import=requests',
        '--hidden-import=cryptography',
        '--exclude-module=matplotlib',
        '--exclude-module=numpy',
        '--exclude-module=scipy',
        '--exclude-module=pandas',
        '--clean',
        'mdb_agent_pro.py'
    ]
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("✅ Build completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        print(f"Output: {e.stdout}")
        print(f"Error: {e.stderr}")
        return False

def create_release_package():
    """Create release package with all necessary files"""
    release_dir = Path('release')
    
    # Create release directory
    release_dir.mkdir(exist_ok=True)
    
    # Copy executable
    exe_source = Path('dist/MDBAgentPro.exe')
    if exe_source.exists():
        shutil.copy2(exe_source, release_dir / 'MDBAgentPro.exe')
        print("✅ Executable copied to release/")
    else:
        print("❌ Executable not found in dist/")
        return False
    
    # Copy essential files
    files_to_copy = [
        'README.md',
        'requirements.txt', 
        'config.example.json',
        'logo-PTSAG.png',
        'run_agent_pro.bat'
    ]
    
    for file_name in files_to_copy:
        source_file = Path(file_name)
        if source_file.exists():
            shutil.copy2(source_file, release_dir / file_name)
            print(f"✅ {file_name} copied")
        else:
            print(f"⚠️ {file_name} not found")
    
    # Create installation guide
    install_guide = """# MDB Agent Pro v2.0 - Installation Guide

## Quick Start
1. Extract all files to a folder (e.g., C:\\MDBAgentPro\\)
2. Double-click MDBAgentPro.exe to run
3. Configure database and API settings
4. Start mapping and processing data

## System Requirements
- Windows 10/11
- Microsoft Access Database Engine
- Network access for API calls

## Support
- Email: freddy.pm@sahabatagro.co.id
- Phone: +62 813-9855-2019
- Company: PT Sahabat Agro Group

© 2025 PT Sahabat Agro Group. All rights reserved.
"""
    
    with open(release_dir / 'INSTALL.md', 'w', encoding='utf-8') as f:
        f.write(install_guide)
    
    print("✅ Release package created")
    return True

def main():
    """Main build process"""
    print("🚀 MDB Agent Pro v2.0 - Build Process Starting...")
    print("=" * 60)
    
    # Step 1: Clean previous builds
    clean_build_directories()
    
    # Step 2: Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Step 3: Build executable
    if not build_executable():
        sys.exit(1)
    
    # Step 4: Create release package
    if not create_release_package():
        sys.exit(1)
    
    print("=" * 60)
    print("🎉 BUILD COMPLETED SUCCESSFULLY!")
    print("📁 Release package available in: release/")
    print("🚀 Ready for deployment: release/MDBAgentPro.exe")
    print("=" * 60)

if __name__ == "__main__":
    main()
