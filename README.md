# Local Security Toolkit

A GUI application for network monitoring and security testing, built with Python and CustomTkinter.

> **Academic Project**  
> **Course:** MO-IT142 - Security Script Programming  
> **Milestone:** 2  
> **Authors:** Maricon Caluya and Jannine Claire Celocia  
> **Repository:** [JCCelocia/SSP-MS2](https://github.com/JCCelocia/SSP-MS2)

---

## Features

### Network Traffic Analyzer
- Real-time packet capture and analysis
- Network interface selection
- Protocol filtering (TCP, UDP, ICMP)
- Port filtering
- Advanced search with field filters (src:, dst:, sport:, dport:, size>X, size<X, size:X-Y)
- IPv4 and IPv6 support
- **Requires administrator/root privileges**

### Port Scanner
- TCP port scanning (1-65535)
- Service identification for common ports
- Real-time progress tracking
- **Only use on systems you own or have permission to test**

---

## Requirements

```bash
Python 3.7+
customtkinter>=5.0.0
scapy>=2.4.5
psutil>=5.8.0  # Optional, for better interface detection
```

---

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/JCCelocia/SSP-MS2.git
cd SSP-MS2
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Application
```bash
# Normal mode
python main.py

# With admin privileges (for network capture)
# Windows: Run Command Prompt as Administrator
# Linux/macOS: sudo python main.py
```

---

## Usage

### Network Traffic Analyzer
1. Select network interface from dropdown
2. Set filters (optional): Protocol and Port
3. Click "Start Capture"
4. Use search box to filter packets:
   - `tcp` - Show TCP packets
   - `src:192.168.1.1` - Filter by source IP
   - `dport:443` - Filter by destination port
   - `size>1000` - Packets larger than 1000 bytes
   - Click "?" button for more help
5. Click "Stop Capture" when done

### Port Scanner
1. Enter target IP or hostname (e.g., 127.0.0.1)
2. Set port range (Start: 20, End: 1024)
3. Set timeout (default: 0.5 seconds)
4. Click "Start Scan"
5. View open ports in green as they're discovered

---

## Project Structure
```
SSP-MS2/
├── main.py              # Application entry point
├── backend.py           # Network and scanning logic
├── frontend.py          # GUI components
├── requirements.txt     # Dependencies
└── README.md           # Documentation
```

---

## Technical Details

- **Architecture:** MVC pattern
- **GUI:** CustomTkinter with dark theme
- **Network Analysis:** Scapy for packet capture
- **Port Scanning:** Python socket library
- **Threading:** Non-blocking operations

---

## Important Notes

⚠️ **Educational purposes only. Use responsibly.**

- Only test systems you own or have explicit permission to test
- Unauthorized scanning may violate laws and policies
- Network capture requires administrator/root privileges
- Packet capture may be subject to wiretapping laws

---

## Troubleshooting

**Missing Dependencies**
```bash
pip install customtkinter scapy psutil
```

**Administrator Privileges Required**
- Windows: Run Command Prompt as Administrator
- Linux/macOS: `sudo python main.py`

**No Open Ports Found**
- Test with localhost (127.0.0.1) first
- Increase timeout value
- Check firewall settings

**Application Won't Start**
```bash
python --version  # Check version (needs 3.7+)
pip install --upgrade -r requirements.txt
```

---

## License & Disclaimer

This project is for educational purposes only. The authors are not responsible for any misuse or damage caused by this software.

**Always ensure you have proper authorization before conducting any security testing.**

---

**Course:** MO-IT142 - Security Script Programming  
**Authors:** Maricon Caluya and Jannine Claire Celocia  
**Repository:** [github.com/JCCelocia/SSP-MS2](https://github.com/JCCelocia/SSP-MS2)  
**Year:** 2025

