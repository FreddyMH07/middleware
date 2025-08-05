# MDB Agent Pro v2.0 🚀

**Professional Database-to-API Bridge for PT Sahabat Agro Group**

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/FreddyMH07/middleware)
[![Python](https://img.shields.io/badge/python-3.10+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://microsoft.com/windows)

## 📋 Overview

MDB Agent Pro adalah aplikasi middleware profesional yang menghubungkan database Microsoft Access (.mdb) dengan REST API endpoints. Dirancang khusus untuk PT Sahabat Agro Group dengan fokus pada integrasi TBS (Tandan Buah Segar) Receiving System.

## ✨ Key Features

### 🔗 **Smart Field Mapping**
- Visual drag-and-drop interface untuk mapping database fields ke API
- Support untuk TBS Receiving API dengan format JSON-RPC 2.0
- Template system untuk konfigurasi yang dapat digunakan ulang
- Real-time JSON preview dengan validasi

### ⚡ **Advanced API Integration**
- Multiple authentication methods (API Key, Login, Bearer Token)
- Smart Mode dengan Test Connection integration
- Automatic retry mechanism untuk failed requests
- Comprehensive error handling dan logging

### 🛡️ **Enterprise Features**
- Health monitoring dan diagnostics
- Transaction logging dengan audit trail
- Automated scheduling untuk data synchronization
- Background processing dengan minimal system impact

### 🎯 **User Experience**
- Modern tabbed interface dengan responsive design
- Context-sensitive help dan validation
- Professional administrative controls
- Comprehensive status indicators

## 🚀 Quick Start

### Prerequisites
```bash
Python 3.10+
Windows 10/11
Microsoft Access Database Engine
```

### Installation

#### Method 1: Run from Source
```bash
# Clone repository
git clone https://github.com/FreddyMH07/middleware.git
cd middleware

# Install dependencies
pip install -r requirements.txt

# Run application
python mdb_agent_pro.py
```

#### Method 2: Executable (Recommended)
```bash
# Download latest release from GitHub
# Extract to desired location
# Run MDBAgentPro.exe
```
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

### Executable Version (No Python Required)

If you prefer a standalone executable that doesn't require Python installation:

1. **Build the executable:**
   ```bash
   # Automatic build
   build.bat
   
   # Or manual build
   python build_exe.py
   ```

2. **Distribute the release:**
   - Copy the entire `release/` folder to target PC
   - Double-click `MDBAgentPro.exe` to run
   - No Python installation required!

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
   - **For Login APIs**: If endpoint contains `/api/auth/login`, fill login credentials:
     - Username/Login
     - Password (masked input)
     - Database name
     - Click "Login / Get Token" to automatically obtain API token
   - **For Direct APIs**: Manually enter API Key/Token
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

### Opsi 2: Build Executable (Recommended for Distribution)

1. **Build menggunakan script otomatis**
   ```bash
   # Double-click atau run:
   build.bat
   
   # Atau manual:
   python build_exe.py
   ```

2. **Distribusi executable**
   - Copy folder `release/` ke PC target
   - Double-click `MDBAgentPro.exe`
   - **Tidak perlu install Python!**

3. **File executable siap distribusi**
   ```
   release/
   ├── MDBAgentPro.exe        # Main executable (25MB)
   ├── config.example.json    # Configuration template
   ├── README.md             # Documentation
   ├── INSTALL.md           # Installation guide
   └── logo-PTSAG.png       # Company logo
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

### 5. 🔐 Login API Configuration
**For APIs that require username/password authentication:**

1. Buka tab **"API Settings"**
2. Masukkan **Endpoint URL** yang mengandung `/api/auth/login` atau `/auth/login`
3. **Login Section** akan muncul otomatis dengan fields:
   - **Username/Login**: Username atau email untuk login
   - **Password**: Password (input ter-mask untuk keamanan)
   - **Database**: Nama database yang digunakan
4. Klik **"Login / Get Token"** untuk otomatis login dan ambil token
5. Jika login berhasil:
   - **API Key/Token** akan otomatis terisi
   - Status akan menampilkan "Login successful!"
   - Token siap digunakan untuk API calls
6. **Save API Settings** untuk menyimpan konfigurasi

**Supported Login Response Formats:**
```json
{
  "access_token": "your_token_here"
}
// atau
{
  "token": "your_token_here"
}
// atau
{
  "jwt": "your_token_here"
}
```

**Troubleshooting Login:**
- ✅ Pastikan endpoint mengandung `/auth/login`
- ✅ Periksa username, password, dan database name
- ✅ Cek koneksi internet dan URL endpoint
- ✅ Pastikan API server berjalan dan dapat diakses

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

### 🚛 TBS Receiving API Integration
**Specialized support for PT Sahabat Agro Group TBS (Tandan Buah Segar) receiving system:**

- **JSON-RPC 2.0 Format**: Compliance with JSON-RPC specification
- **Nested Order Data**: Support for complex order_data structure
- **Template Categories**: Built-in TBS Receiving templates
- **Real-time Validation**: TBS-specific field validation
- **Quality Parameters**: Support for TBS quality metrics

**TBS API Format Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "receive_order",
  "params": {
    "order_data": {
      "order_id": "ORD001",
      "supplier_code": "SUP001",
      "delivery_date": "2025-01-15",
      "total_weight": 1250.5,
      "quality_grade": "A",
      "moisture_content": 21.5,
      "dirt_content": 2.1,
      "bunch_count": 125
    }
  },
  "id": 1
}
```

## 📝 Struktur Data

### Format Payload API Standar
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

### Format TBS Receiving API (JSON-RPC 2.0)
```json
{
  "jsonrpc": "2.0",
  "method": "receive_order",
  "params": {
    "order_data": {
      "order_id": "TBS-ORD-20250115-001",
      "supplier_code": "SUP001",
      "supplier_name": "Kebun Sawit Makmur",
      "delivery_date": "2025-01-15",
      "delivery_time": "08:30:00",
      "vehicle_number": "B1234ABC",
      "driver_name": "Ahmad Suharto",
      "total_weight": 1250.5,
      "tare_weight": 8500.0,
      "net_weight": 1242.0,
      "quality_grade": "A",
      "moisture_content": 21.5,
      "dirt_content": 2.1,
      "foreign_matter": 0.5,
      "bunch_count": 125,
      "loose_fruit_kg": 15.2,
      "rotten_bunches": 2,
      "empty_bunches": 1,
      "long_stalk": 3,
      "price_per_kg": 1850,
      "total_amount": 2297700,
      "payment_method": "Transfer",
      "notes": "Kualitas bagus, pengiriman tepat waktu",
      "inspector_name": "Budi Santoso",
      "created_by": "operator1",
      "location_code": "REC001"
    }
  },
  "id": 1
}
```

### HTTP Headers
```
Content-Type: application/json
Authorization: Bearer <your-api-key>
```

## ⚙️ Configuration Examples

### Standard API Configuration
```json
{
  "api_endpoint": "https://api.example.com/data",
  "api_key": "your-standard-api-key",
  "authentication_type": "api_key",
  "field_mapping": {
    "ID": "id",
    "Name": "name", 
    "Timestamp": "timestamp",
    "Value": "value"
  }
}
```

### TBS Receiving API Configuration
```json
{
  "api_endpoint": "https://tbs-api.sahabatagro.co.id/api/receive",
  "api_key": "tbs-receiving-token",
  "authentication_type": "bearer",
  "api_format": "json-rpc-2.0",
  "rpc_method": "receive_order",
  "field_mapping": {
    "OrderID": "order_data.order_id",
    "SupplierCode": "order_data.supplier_code",
    "SupplierName": "order_data.supplier_name",
    "DeliveryDate": "order_data.delivery_date",
    "DeliveryTime": "order_data.delivery_time",
    "VehicleNumber": "order_data.vehicle_number",
    "DriverName": "order_data.driver_name",
    "TotalWeight": "order_data.total_weight",
    "TareWeight": "order_data.tare_weight",
    "NetWeight": "order_data.net_weight",
    "QualityGrade": "order_data.quality_grade",
    "MoistureContent": "order_data.moisture_content",
    "DirtContent": "order_data.dirt_content",
    "ForeignMatter": "order_data.foreign_matter",
    "BunchCount": "order_data.bunch_count",
    "LooseFruitKg": "order_data.loose_fruit_kg",
    "RottenBunches": "order_data.rotten_bunches",
    "EmptyBunches": "order_data.empty_bunches",
    "LongStalk": "order_data.long_stalk",
    "PricePerKg": "order_data.price_per_kg",
    "TotalAmount": "order_data.total_amount",
    "PaymentMethod": "order_data.payment_method",
    "Notes": "order_data.notes",
    "InspectorName": "order_data.inspector_name",
    "CreatedBy": "order_data.created_by",
    "LocationCode": "order_data.location_code"
  }
}
```

### Login-based API Configuration  
```json
{
  "api_endpoint": "https://api.example.com/api/auth/login",
  "authentication_type": "login",
  "login_credentials": {
    "username": "your_username",
    "password": "your_password", 
    "database": "production_db"
  },
  "token_endpoint": "/api/auth/login",
  "data_endpoint": "/api/data"
}
```

## ⚙️ Konfigurasi File
https://web-middlware-production.up.railway.app//api/auth/login 
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

## 🛠️ Development & Build

### Project Structure (Final Clean Version)
```
middleware/
├── mdb_agent_pro.py         # Main application (8746+ lines)
├── build_exe.py             # Professional build script
├── requirements.txt         # Dependencies with comments
├── run_agent_pro.bat       # Windows launcher script
├── config.example.json      # Configuration template
├── logo-PTSAG.png          # PT Sahabat Agro Group logo
├── README.md               # Complete documentation
├── .gitignore              # Git ignore rules
├── .git/                   # Git repository
├── release/                # Build output directory
│   ├── MDBAgentPro.exe    # Standalone executable
│   ├── INSTALL.md         # Installation guide
│   └── (support files)    # Required runtime files
├── agent_data.db          # SQLite buffer database
├── agent.log              # Application logs
└── config.encrypted       # Encrypted configuration
```

### Core Features Implementation
- **✅ Smart Mode Architecture** - Complete Test Connection integration
- **✅ TBS Receiving API** - JSON-RPC 2.0 support with nested structure
- **✅ Professional GUI** - Modern tabbed interface with dark theme
- **✅ Enterprise Security** - AES encryption, admin controls, audit logging
- **✅ Template System** - Save/load field mapping configurations
- **✅ Real-time Monitoring** - Health checks, status indicators, logging
- **✅ Robust Error Handling** - Retry mechanisms, buffer system, validation

### Technologies Used
- **Python 3.8+**: Core application framework
- **Tkinter**: Cross-platform GUI framework
- **PyODBC**: Microsoft Access database connectivity
- **Requests**: HTTP API communication with retry logic
- **Cryptography**: AES encryption for secure configuration
- **SQLite3**: Local buffer and logging database
- **PyInstaller**: Executable packaging and distribution

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
