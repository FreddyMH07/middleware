# MDB Agent Pro v2.0

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://microsoft.com/windows)

**Professional Microsoft Access Database to API Bridge**

Developed by **Freddy Mazmur** for **PT Sahabat Agro Group**

---

## 🚀 Overview

MDB Agent Pro is a professional desktop application that bridges Microsoft Access databases to REST APIs with visual field mapping, real-time monitoring, and enterprise-grade features.

## ✨ Key Features

### 🔗 **Database Connectivity**
- **Visual File Selection** - Browse and select .mdb/.accdb files
- **Password Protection** - Secure database access with encryption
- **Auto Table Detection** - Automatic discovery of database tables
- **Real-time Preview** - Live data preview and validation
- **Connection Health Monitoring** - Continuous connection status tracking

### 🎯 **Visual Field Mapping**
- **Drag-and-Drop Interface** - Intuitive field mapping system
- **API Structure Import** - Import from JSON specifications or auto-detect
- **Data Transformations** - Built-in data formatting and conversion
- **Template Management** - Save and reuse mapping configurations
- **Real-time JSON Preview** - Live preview of API payload
- **Mapping Validation** - Comprehensive validation and error checking

### 📊 **Enterprise Monitoring**
- **Transaction Logging** - Detailed audit trails and statistics
- **Health Dashboards** - Real-time system health monitoring
- **API Performance Tracking** - Response time and error rate monitoring
- **Automated Scheduling** - Background data synchronization
- **Buffer Management** - Offline resilience and retry mechanisms

### 🛡️ **Professional Features**
- **Multi-threaded Processing** - Efficient background operations
- **Comprehensive Logging** - Detailed application and error logs
- **Admin Controls** - Secure administrative functions
- **Theme Support** - Light and dark mode interface
- **Configuration Management** - JSON-based settings with encryption

## 🔧 Installation

### Prerequisites
- **Windows 7/8/8.1/10/11** (32-bit or 64-bit)
- **Python 3.7 or higher** (recommended: Python 3.8+)
- **Microsoft Access Database Engine** (for .mdb/.accdb support)

> **⚠️ Windows 7 Compatibility Notes:**
> - Windows 7 support requires Python 3.7-3.8 (Python 3.9+ dropped Win7 support)
> - Microsoft Access Database Engine 2016+ recommended
> - Some modern TLS features may require updates
> - Windows 7 reached End of Life (EOL) in January 2020

> **✅ Recommended Platforms:**
> - **Windows 10/11**: Full support with all features
> - **Windows 8/8.1**: Fully supported
> - **Windows 7**: Basic support with limitations

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/FreddyMH07/middleware.git
   cd middleware
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the application:**
   ```bash
   # Copy the example configuration
   copy config.example.json config.json
   # Edit config.json with your settings
   ```

4. **Run the application:**
   ```bash
   # Using Python
   python mdb_agent_pro.py
   
   # Or using the batch file (Windows)
   run_agent_pro.bat
   ```

### Windows 7 Installation Notes

If you're installing on Windows 7, follow these additional steps:

1. **Install Python 3.8 (last version supporting Windows 7):**
   ```
   Download from: https://www.python.org/downloads/release/python-3811/
   Choose: Windows x86-64 executable installer (for 64-bit)
   Or: Windows x86 executable installer (for 32-bit)
   ```

2. **Install Microsoft Visual C++ Redistributable:**
   ```
   Download Microsoft Visual C++ 2015-2019 Redistributable
   Required for pyodbc and other native modules
   ```

3. **Install Microsoft Access Database Engine:**
   ```
   Download Access Database Engine 2016 Redistributable
   Choose matching architecture (32-bit or 64-bit)
   ```

4. **Update Windows certificates (if needed):**
   ```
   Run Windows Update to get latest root certificates
   Required for HTTPS API connections
   ```

## 📖 Usage Guide

### Initial Setup

1. **Database Configuration**
   - Open the "Database Connection" tab
   - Browse and select your Microsoft Access database file
   - Enter the database password (default: qwerty123)
   - Select the table you want to sync

2. **API Configuration**
   - Navigate to "API Settings" tab
   - Enter your API endpoint URL
   - Configure authentication (API key/token)
   - Test the connection

3. **Field Mapping**
   - Go to "API Field Mapping" tab
   - Map database columns to API fields
   - Configure data transformations if needed
   - Save your mapping as a template
   - Validate and test the mapping

4. **Start Synchronization**
   - Configure push interval in "Scheduler" tab
   - Enable automatic push
   - Start the agent

### Key Operations

- **Manual Data Push:** Use the "Manual Push" button for immediate synchronization
- **Health Monitoring:** Check the "Health Checks" tab for system status
- **Transaction History:** View detailed logs in "Transaction Log" tab
- **Template Management:** Save and reuse field mappings for different tables

## 🔐 Security

- **Encrypted Configuration:** Sensitive data is encrypted at rest
- **Secure API Communication:** HTTPS-only API calls with proper authentication
- **Admin Mode:** Administrative functions require PIN authentication
- **Audit Logging:** Comprehensive logging for security and compliance

## 🛠️ Technical Specifications

- **Language:** Python 3.8+
- **GUI Framework:** Tkinter (cross-platform)
- **Database Connectivity:** ODBC (pyodbc)
- **HTTP Client:** Requests with retry logic
- **Local Storage:** SQLite3 for logging and buffering
- **Configuration:** JSON with optional encryption

## 📁 Project Structure

```
AgentUI/
├── mdb_agent_pro.py           # Main application
├── requirements.txt           # Python dependencies
├── config.example.json        # Configuration template
├── run_agent_pro.bat         # Windows launcher
├── logo-PTSAG.png            # Company logo
├── README.md                 # This file
├── .gitignore               # Git ignore rules
└── .github/                 # GitHub configuration
```

## 🐛 Troubleshooting

### Common Issues

1. **"Database connection failed"**
   - Verify the database file path is correct
   - Check if the database password is accurate
   - Ensure Microsoft Access Database Engine is installed

2. **"API connection timeout"**
   - Verify the API endpoint URL
   - Check your internet connection
   - Validate API key/token

3. **"Field mapping validation failed"**
   - Ensure all required fields are mapped
   - Check for duplicate API field mappings
   - Verify data transformation settings

4. **Windows 7 Specific Issues**
   - **"SSL Certificate Error"**: Update Windows certificates via Windows Update
   - **"Module import failed"**: Install Visual C++ Redistributable 2015-2019
   - **"Python version error"**: Use Python 3.7 or 3.8 (maximum for Windows 7)
   - **"Slow performance"**: Disable visual effects, increase virtual memory

5. **Database Engine Issues**
   - **"Provider not found"**: Install matching Access Database Engine (32/64-bit)
   - **"Permission denied"**: Run as Administrator on first setup
   - **"File access error"**: Check file permissions and antivirus settings

### Support

For technical support and assistance:

- **Email:** freddy.pm@sahabatagro.co.id
- **Phone:** +62 813-9855-2019
- **Company:** PT Sahabat Agro Group
- **Hours:** Monday-Friday, 8:00 AM - 6:00 PM (WIB)

## 📄 License

This software is proprietary and confidential. Unauthorized copying, distribution, or modification is strictly prohibited.

**© 2025 PT Sahabat Agro Group. All rights reserved.**

---

**Developed with ❤️ by Freddy Mazmur**

#### 3. **Core Agent Logic**
- **✅ Latest Record Detection** - Ambil baris terbaru berdasarkan ID terbesar/timestamp
- **✅ HTTP POST dengan Authorization** - API Key di header Authorization  
- **✅ JSON Config Storage** - Semua setting disimpan di config.json
- **✅ Buffer System** - Simpan data yang gagal kirim, retry otomatis
- **✅ Background Worker** - Auto push sesuai interval yang diatur
- **✅ Field Mapping with Transformations** - Apply mapping dan transformasi data

### 🎨 Clean & Simple Interface
- **Dashboard**: Overview sistem dan monitoring status
- **Configuration**:
  - Database Connection (Koneksi Database)
  - API Field Mapping (Mapping Field API)
- **Information**:
  - About Application (Tentang Aplikasi)
- **Status Indicators**: Lampu indikator berwarna (hijau/kuning/merah) untuk status database, API, dan buffer

### 🔒 Security & Configuration
- **Encrypted Configuration**: Konfigurasi tersimpan dengan enkripsi AES
- **Admin PIN Protection**: PIN khusus untuk mengakses fitur konfigurasi lanjutan
- **Secure Password Fields**: Field password tersembunyi untuk keamanan

### 🗃️ Advanced Database Management
- **Flexible File Selection**: File picker untuk memilih database .mdb/.accdb
- **Password Protection**: Dukungan database yang diproteksi password
- **Table Preview**: Preview tabel dengan data sample
- **Column Detection**: Otomatis mendeteksi kolom dan tipe data

### 🔗 User-Friendly Field Mapping
- **Visual Field Mapping**: Interface intuitif dengan dropdown selection
- **No-Code Required**: Semua dilakukan melalui GUI, tanpa edit file
- **Auto-Detection**: Auto-detect struktur API dari endpoint atau JSON
- **Data Transformations**: Built-in transformasi untuk text, number, date
- **Template System**: Simpan dan muat template mapping untuk reuse
- **Real-time Preview**: Preview JSON payload yang update otomatis
- **Validation System**: Cek mapping sebelum push data

### 🌐 Enhanced API Integration
- **Configurable Endpoints**: Set URL endpoint dan API key
- **Test Mode**: Mode simulasi tanpa mengirim data real
- **Payload Preview**: Preview payload sebelum dikirim
- **UUID Generation**: UUID unik untuk setiap data mencegah duplikasi
- **Field Mapping**: Apply mapping dan transformasi sebelum kirim

### 📊 Smart Monitoring
- **Real-time Dashboard**: Status koneksi dan aktivitas real-time
- **Comprehensive Logging**: Log detail dengan timestamp
- **Buffer Management**: Queue otomatis untuk data yang gagal dikirim
- **Exponential Backoff**: Strategi retry dengan exponential backoff
- **Status Monitoring**: Monitor health database dan API connection

### ⚡ Intelligent Scheduler
- **Flexible Intervals**: Interval push 5 menit hingga 1 jam
- **Auto-Push**: Push otomatis berdasarkan jadwal
- **Manual Override**: Push manual kapan saja
- **Background Processing**: Worker thread untuk proses background

## 📋 System Requirements

### Supported Operating Systems
- **✅ Windows 11** - Fully supported, recommended
- **✅ Windows 10** - Fully supported, all features available
- **✅ Windows 8.1** - Fully supported
- **✅ Windows 8** - Fully supported  
- **⚠️ Windows 7** - Basic support with limitations*

### Hardware Requirements
- **CPU**: 1 GHz processor (dual-core recommended)
- **RAM**: Minimum 1GB, Recommended 2GB+
- **Storage**: 100MB free space for application
- **Network**: Internet connection for API synchronization

### Software Dependencies
- **Python Runtime**: 3.7+ (Windows 7), 3.8+ (Windows 8+)
- **Microsoft Access Database Engine**: 2010, 2013, 2016, or 2019
- **Visual C++ Redistributable**: May be required for some components

### *Windows 7 Limitations
- **Python Version**: Limited to Python 3.7-3.8 (newer versions don't support Win7)
- **TLS/SSL**: May require manual certificate updates for HTTPS APIs
- **Performance**: Slower performance on older hardware
- **Support**: Microsoft ended Windows 7 support in January 2020
- **Recommendation**: Upgrade to Windows 10/11 for optimal experience

## 🚀 Instalasi & Setup

### Opsi 1: Menjalankan dari Source Code

1. **Clone repository**
   ```bash
   git clone https://github.com/FreddyMH07/middleware.git
   cd middleware
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Jalankan aplikasi**
   ```bash
   python mdb_agent_pro.py
   ```

### Opsi 2: Build Executable

1. **Automated build**
   ```bash
   python build.py
   ```

2. **Manual build**
   ```bash
   pip install -r requirements.txt
   pyinstaller --onefile --windowed --name=MDBAgentPro mdb_agent_pro.py
   ```

3. **Executable tersedia di**
   ```
   dist/MDBAgentPro.exe
   ```

## 📖 Panduan Penggunaan

### 1. 🔐 Admin Mode
- Klik tombol **"Admin Mode"** di sidebar
- Masukkan PIN (default: `1234`)
- Mode admin diperlukan untuk konfigurasi lanjutan

### 2. 🗃️ Konfigurasi Database
1. Buka tab **"Database Connection"**
2. Klik **"Browse"** untuk pilih file .mdb/.accdb
3. Masukkan **password** database (default: qwerty123)
4. Klik **"Connect Database"**
5. Pilih **tabel** dari dropdown
6. Review **preview data** di tabel bawah
7. Isi **API Endpoint** dan **API Key**
8. Pilih **Push Interval** (5 menit - 1 jam)
9. Centang **"Enable Automatic Push"** jika ingin auto push
10. Klik **"Save Configuration"**

### 3. 🔗 API Field Mapping
1. Buka tab **"API Field Mapping"**
2. **Setup API Fields** terlebih dahulu:
   - **Import API Spec**: Upload file JSON struktur API
   - **Auto Detect**: Biarkan sistem detect struktur dari endpoint
   - **Manual Entry**: Input field API secara manual
3. **Map Database Fields**:
   - Setiap kolom database akan muncul di kiri
   - Pilih **API Field** dari dropdown di kanan
   - Atau isi **Custom Field** untuk field baru
   - Pilih **Transformation** jika perlu (format tanggal, uppercase, dll)
4. **Preview & Test**:
   - Lihat **JSON Preview** di panel kanan
   - Klik **"Validate Mapping"** untuk cek error
   - Klik **"Test API Call"** untuk test dengan data sample
5. **Save Template**:
   - Klik **"Save"** di Template section
   - Beri nama template untuk reuse
6. **Load Template**:
   - Pilih template dari list
   - Klik **"Load"** untuk apply

### 4. 📊 Dashboard Monitoring
1. Buka tab **"Dashboard"**
2. Monitor status sistem real-time:
   - **Database Status**: Hijau = connected, Merah = error
   - **API Status**: Hijau = OK, Kuning = warning, Merah = error
   - **Buffer Status**: Monitor jumlah data pending
3. Gunakan **Quick Actions**:
   - **Test Database**: Test koneksi database
   - **Test API**: Test koneksi API
   - **Manual Push**: Push data manual
   - **Start Agent**: Mulai auto push
   - **Stop Agent**: Stop auto push
   - **Clear Buffer**: Clear data pending

## 🔧 Fitur Advanced

### 🛡️ Security Features
- **Encrypted Config**: Semua konfigurasi disimpan terenkripsi
- **Admin PIN**: PIN untuk akses fitur administrator
- **Secure Fields**: Password fields tersembunyi dari view

### 🔄 Buffer & Retry System
- **SQLite Buffer**: Data disimpan di database lokal jika push gagal
- **Auto Retry**: Retry otomatis dengan exponential backoff
- **Max Retries**: Maksimal 5 kali retry sebelum marked as failed
- **Buffer Monitoring**: Monitor jumlah item di buffer

### 🔗 Field Mapping & Transformations
- **Visual Mapping**: Drag-and-drop interface untuk mapping
- **Data Transformations**: Built-in transformasi untuk berbagai tipe data
- **Template System**: Save/load template untuk reuse
- **Validation**: Real-time validation mapping
- **API Structure Detection**: Auto-detect dari endpoint atau JSON file

### 📤 Data Flow & UUID
- **UUID Generation**: Setiap data diberi UUID unik
- **Metadata Injection**: Metadata otomatis (timestamp, source table, version)
- **Duplicate Prevention**: UUID mencegah duplikasi data
- **Field Mapping**: Apply transformasi sebelum kirim ke API

## 📝 Struktur Data

### Format Payload API
```json
{
  "id": 1001,
  "name": "Sample Data",
  "timestamp": "2025-01-15 10:30:00",
  "value": 123.45,
  "status": "Active",
  "_metadata": {
    "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2025-01-15T10:30:00",
    "source_table": "DataTable",
    "agent_version": "2.0.0"
  }
}
```

### HTTP Headers
```
Content-Type: application/json
Authorization: Bearer <your-api-key>
```

## ⚙️ Konfigurasi File

File `config.encrypted` otomatis dibuat dengan enkripsi AES:
```json
{
  "mdb_file": "C:/path/to/database.mdb",
  "mdb_password": "qwerty123",
  "selected_table": "DataTable",
  "field_mapping": {
    "ID": "id",
    "Name": "name",
    "Timestamp": "timestamp"
  },
  "api_endpoint": "https://api.example.com/data",
  "api_key": "your-api-key",
  "push_interval": 300,
  "auto_push": true,
  "test_mode": false,
  "admin_pin": "1234",
  "dark_mode": false
}
```

## 🛠️ Development

### Project Structure
```
AgentUI/
├── mdb_agent_pro.py         # Main application (Pro version)
├── mdb_agent.py             # Legacy simple version
├── requirements.txt         # Dependencies
├── build.py                 # Build script
├── test.py                  # Test utilities
├── config.example.json      # Example configuration
├── config.encrypted         # Encrypted config (auto-generated)
├── agent_data.db           # SQLite database (auto-generated)
├── agent.log               # Application log (auto-generated)
├── README.md               # Documentation
└── .github/
    └── copilot-instructions.md
```

### Dependencies
- **pyodbc**: Microsoft Access database connectivity
- **requests**: HTTP API communication
- **cryptography**: AES encryption for configuration
- **sqlite3**: Local buffer database (built-in)
- **tkinter**: GUI framework (built-in)
- **pyinstaller**: Executable packaging

### Running Tasks
```bash
# Run MDB Agent Pro
python mdb_agent_pro.py

# Run tests
python test_pro.py

# Build executable
python build.py
```

## 🔍 Troubleshooting

### Common Issues

#### Database Connection
```
Error: Failed to connect to database
Solutions:
✓ Pastikan file .mdb dapat diakses
✓ Periksa password database
✓ Install Microsoft Access Database Engine
✓ Periksa permissions file
```

#### API Connection
```
Error: API request failed
Solutions:
✓ Periksa koneksi internet
✓ Validasi URL endpoint
✓ Periksa API key authorization
✓ Review firewall settings
```

#### Encryption Issues
```
Error: Failed to decrypt configuration
Solutions:
✓ Reset configuration dari About tab
✓ Periksa cryptography library installation
✓ Hapus config.encrypted dan restart
```

#### Buffer Issues
```
Error: High buffer count
Solutions:
✓ Periksa koneksi API
✓ Clear buffer dari Dashboard
✓ Restart agent service
```

### Diagnostic Steps
1. **Check Dashboard** status indicators
2. **Review Logs** di tab Scheduler/Log
3. **Test Components** secara individual
4. **Export Logs** untuk analisis
5. **Contact IT** jika masalah persisten

## 📞 Support & Maintenance

### IT Support Features
- **Send Log to IT**: Export log untuk tim support
- **System Information**: Info versi dan platform
- **Configuration Reset**: Reset konfigurasi jika bermasalah
- **Update Check**: Periksa update (placeholder)

### Maintenance Tasks
- **Regular Log Cleanup**: Clear log secara berkala
- **Buffer Monitoring**: Monitor buffer size
- **Configuration Backup**: Backup konfigurasi penting
- **Performance Monitoring**: Monitor performance agent

## 📄 License & Legal

© 2025 Enterprise Solutions. All rights reserved.

Software ini dilisensikan untuk penggunaan internal organisasi.
Redistribusi atau modifikasi tanpa izin tertulis dilarang.

**Technical Support:**
- Email: support@company.com
- Phone: +1-555-0123
- Hours: 24/7 untuk critical issues

---

**MDB Agent Pro v2.0** - Professional Microsoft Access Database to API Bridge Solution dengan Enterprise-Grade Features
