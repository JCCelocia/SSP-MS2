# Local Security Toolkit

A comprehensive GUI application for system monitoring and network security testing, built with Python and CustomTkinter.

> **Academic Project**  
> **Course:** MO-IT142 - Security Script Programming  
> **Milestone:** 2  
> **Authors:** Maricon Caluya and Jannine Claire Celocia  
> **Repository:** [JCCelocia/SSP-MS2](https://github.com/JCCelocia/SSP-MS2)

---

## Overview

Local Security Toolkit is an educational cybersecurity application designed for system monitoring and authorized security testing. It provides a modern, dark-themed GUI with an intuitive welcome screen for performing common security assessments and system diagnostics.

**Purpose:** Educational and authorized security testing only

---

## Features

### 1. Welcome Screen
- Modern main menu with module selection
- Quick access to all tools

### 2. System Information
- Display operating system details
- Show CPU core count and memory usage
- Monitor system uptime with color-coded alerts
- Real-time refresh capability

### 3. Network Traffic Analyzer
- Real-time packet capture and analysis
- Protocol filtering (TCP, UDP, ICMP)
- Port-based filtering
- IPv4 and IPv6 support
- **Requires administrator/root privileges**

### 4. Port Scanner
- TCP port scanning with customizable range
- Service identification for common ports
- Real-time progress tracking
- **Only use on systems you own or have permission to test**

### 5. About
- Application information
- Tool descriptions
- Usage guidelines and safety reminders

---

## Requirements

### Required
```bash
Python 3.7+
customtkinter>=5.0.0
```

### Optional (for full functionality)
```bash
psutil>=5.8.0          # System Information feature
scapy>=2.4.5           # Network Traffic Analyzer
```

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/JCCelocia/SSP-MS2.git
cd SSP-MS2
```

### 2. Install Dependencies
```bash
# Install all dependencies from requirements.txt
pip install -r requirements.txt

# Or install individually:
# Required only
pip install customtkinter

# Required + Optional (recommended)
pip install customtkinter psutil scapy
```

### 3. Run the Application
```bash
python main.py
```

**For Network Traffic Capture (requires admin privileges):**
- **Windows:** Right-click Command Prompt → "Run as Administrator" → `python main.py`
- **Linux/macOS:** `sudo python main.py`

---

## Usage

### Welcome Screen
1. Launch the application with `python main.py`
2. You'll see the welcome screen with all available modules
3. Click on any module card to launch that tool
4. Use the sidebar to navigate or return to Welcome at any time

### System Information
1. Click "System Info" from the welcome screen or sidebar
2. View system details and memory usage
3. Click "Refresh" to update

### Network Traffic Analyzer
1. Click "Network Traffic" from the welcome screen or sidebar
2. Set filters (optional): Protocol and Port
3. Click "Start Capture"
4. Monitor packets in real-time
5. Click "Stop Capture" when done

### Port Scanner
1. Click "Port Scanner" from the welcome screen or sidebar
2. Configure scan parameters:
   - **Target:** IP address or hostname (e.g., 127.0.0.1)
   - **Port Range:** Start and end port (1-65535)
   - **Timeout:** Connection timeout in seconds
3. Click "Start Scan"
4. View results in real-time

---

## Project Structure
```
SSP-MS2/
├── main.py              # Application entry point
├── backend.py           # Backend logic and data processing
├── frontend.py          # GUI components and layouts
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

---

## Technical Details

### Architecture
- **Pattern:** Model-View-Controller (MVC)
- **Threading:** Daemon threads for long operations
- **UI Framework:** CustomTkinter (dark theme)
- **Resource Management:** Context managers for socket cleanup

### Key Technologies
- **GUI:** CustomTkinter
- **System Monitoring:** psutil
- **Network Analysis:** scapy
- **Networking:** socket, threading

---

## Important Notes

### Ethical Usage
⚠️ **This tool is for educational purposes only.**

- Only test systems you own or have explicit permission to test
- Unauthorized scanning may violate laws and policies
- Always get written permission before security testing
- Respect your organization's security policies

### Safety Features
- Clear warning messages on potentially dangerous features
- Confirmation dialogs for operations
- Timeout protection on network operations
- Rate limiting to avoid overwhelming targets

---

## Troubleshooting

### "customtkinter is required"
```bash
pip install customtkinter
```

### "Administrator privileges required"
Network traffic capture needs elevated privileges:
- **Windows:** Run Command Prompt as Administrator
- **Linux/macOS:** Use `sudo python main.py`

### Port Scanner finds no open ports
- Try scanning localhost (127.0.0.1) first
- Increase timeout value
- Check firewall settings

### Application won't start
```bash
# Check Python version
python --version  # Should be 3.7+

# Reinstall dependencies
pip install --upgrade customtkinter psutil scapy
```

---

## License & Disclaimer

This project is intended for educational purposes as part of the MO-IT142 course. The authors are not responsible for any misuse or damage caused by this software. Always ensure you have proper authorization before conducting any security testing.

---

**Course:** MO-IT142 - Security Script Programming  
**Project:** Milestone 2  
**Authors:** Maricon Caluya and Jannine Claire Celocia  
**Repository:** [github.com/JCCelocia/SSP-MS2](https://github.com/JCCelocia/SSP-MS2)  
**Year:** 2025
