# MDB Agent Pro

**Enterprise Database Synchronization Tool for TBS (Timbangan Basah Segar) Integration**

## 📋 Quick Start

1. **Read the User Manual**: [USER_MANUAL.md](USER_MANUAL.md) - Complete usage guide
2. **Run the application**: `python mdb_agent_pro.py` or `run_agent_pro.bat`
3. **Configure database connection** in Database Connection tab
4. **Setup API authentication** in API Settings tab
5. **Configure field mapping** in Field Mapping tab

## 🎯 Key Features

- ✅ **Microsoft Access Database Integration**
- ✅ **TBS API Integration with JSON-RPC Support** 
- ✅ **Advanced Field Mapping Engine**
- ✅ **Real-time Data Synchronization**
- ✅ **Secure Authentication & Encryption**
- ✅ **Comprehensive Monitoring & Logging**

## 📖 Documentation

- **[USER_MANUAL.md](USER_MANUAL.md)** - Complete user guide with step-by-step instructions
- **[REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md)** - Technical architecture and improvements
- **[config.example.json](config.example.json)** - Configuration template

## 🚀 Quick Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run application
python mdb_agent_pro.py
```

## ⚡ Quick Configuration

### Database Setup:
1. Browse to your MDB file
2. Enter database password if required
3. Select table to synchronize

### API Setup:
1. **Login URL**: `https://web-middlware-production.up.railway.app/api/auth/login`
2. **TBS API**: `https://web-middlware-production.up.railway.app/api/receiving-tbs/create`
3. **Credentials**: `admin / SAGsecure#2025 / sag_production`

### Field Mapping:
1. Select **TBS Auto** mode
2. Load **TBS Preset** template
3. Map database fields to API structure
4. Test mapping functionality

## 🛠️ Technical Stack

- **Python 3.8+** - Core application
- **Tkinter** - GUI framework
- **Requests** - HTTP client
- **Cryptography** - Security & encryption
- **JSON-RPC 2.0** - API communication protocol

## 🔧 Architecture

The application uses a modular architecture with these components:

- **`mdb_agent_pro.py`** - Main application
- **`utils/`** - Utility modules:
  - `security.py` - Authentication & encryption
  - `database_manager.py` - Database operations
  - `gui_utils.py` - GUI components & FieldMapper
  - `logging_manager.py` - Logging system

## 📊 System Requirements

- **OS**: Windows 10/11
- **Python**: 3.8 or higher
- **Database**: Microsoft Access (MDB files)
- **Network**: Internet connection for API calls
- **Memory**: 512MB RAM minimum

## 🆘 Support

- **Company**: PT Sahabat Agro Group
- **Developer**: Freddy Mazmur
- **Version**: 2.0 (Enhanced Field Mapping)

For detailed instructions, troubleshooting, and advanced features, see **[USER_MANUAL.md](USER_MANUAL.md)**.

---

*Last Updated: August 5, 2025*
