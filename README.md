# Local Security Toolkit

A comprehensive GUI application for system monitoring and network security testing, built with Python and CustomTkinter.

> **Academic Project**  
> **Course:** MO-IT142 - Security Script Programming  
> **Milestone:** 2  
> **Authors:** Maricon Caluya and Jannine Claire Celocia

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Code Structure](#code-structure)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## 🎯 Overview

Local Security Toolkit is an educational cybersecurity application designed for system monitoring and authorized security testing. It provides a modern, dark-themed GUI for performing common security assessments and system diagnostics.

**Purpose**: Educational and authorized security testing only  
**Version**: 1.0  
**Python**: 3.7+

## ✨ Features

### 1. System Information
- Display operating system details
- Show CPU core count
- Monitor memory usage with visual progress bar
- Track system uptime with color-coded alerts
- Real-time refresh capability

### 2. Network Traffic Analyzer
- Real-time packet capture and analysis
- Protocol filtering (TCP, UDP, ICMP, All)
- Port-based filtering
- IPv4 and IPv6 support
- Live packet count tracking
- Detailed packet information display
- **Requires**: Administrator/root privileges

### 3. Port Scanner
- TCP port scanning
- Customizable port range (1-65535)
- Adjustable timeout settings
- Service identification for common ports
- Real-time progress tracking
- Open port detection and reporting
- Scan statistics and timing

## 📦 Requirements

### Required Dependencies
```bash
customtkinter>=5.0.0    # Modern UI framework
```

### Optional Dependencies
```bash
psutil>=5.8.0          # System information (System Info feature)
scapy>=2.4.5           # Packet capture (Network Traffic Analyzer)
```

### System Requirements
- Python 3.7 or higher
- Windows, macOS, or Linux
- Administrator/root privileges (for network traffic capture)

## 🚀 Installation

### 1. Clone or Download the Repository
```bash
git clone <repository-url>
cd local-security-toolkit
```

### 2. Install Required Dependencies
```bash
pip install customtkinter
```

### 3. Install Optional Dependencies
```bash
# For full functionality
pip install psutil scapy

# Or install individually
pip install psutil    # For System Information
pip install scapy     # For Network Traffic Analyzer
```

### 4. Run the Application
```bash
python main.py
```

#### Running with Administrator Privileges (for Network Traffic Capture)

**Linux/macOS**:
```bash
sudo python main.py
```

**Windows**:
- Right-click Command Prompt or PowerShell
- Select "Run as Administrator"
- Navigate to the directory and run: `python main.py`

## 💻 Usage

### Starting the Application
```bash
python main.py
```

### Navigation
- Use the sidebar buttons to switch between features
- Each feature has its own dedicated interface
- Click "About" for feature descriptions and usage guidelines

### System Information
1. Click "System Info" in the sidebar
2. View current system statistics
3. Click "Refresh" to update information

### Network Traffic Analyzer
1. Click "Network Traffic" in the sidebar
2. Set filters (optional):
   - Protocol: Select TCP, UDP, ICMP, or All
   - Port: Enter specific port number to filter
3. Click "Start Capture" to begin packet capture
4. Monitor captured packets in real-time
5. Click "Stop Capture" to end capture
6. Click "Clear Display" to reset the packet table

**Note**: Requires administrator/root privileges

### Port Scanner
1. Click "Port Scanner" in the sidebar
2. Configure scan parameters:
   - **Target**: IP address or hostname (e.g., 127.0.0.1, google.com)
   - **Start Port**: Beginning of port range (1-65535)
   - **End Port**: End of port range (1-65535)
   - **Timeout**: Connection timeout in seconds (e.g., 0.5)
3. Click "Start Scan" to begin
4. Monitor progress and results in real-time
5. Click "Stop Scan" to halt the scan early
6. Click "Clear Results" to reset the results table

**Warning**: Only scan systems you own or have permission to test

## 🏗️ Architecture

### Design Pattern
The application follows a **Model-View-Controller (MVC)** pattern with clear separation between backend logic and frontend UI.

```
┌─────────────────────────────────────────┐
│          main.py (Entry Point)          │
│  - Dependency checking                  │
│  - Application lifecycle management     │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
┌───────▼─────────┐  ┌─────▼────────────┐
│   frontend.py   │  │   backend.py     │
│   (UI Layer)    │  │  (Logic Layer)   │
│                 │  │                  │
│ - MainApp       │  │ - SystemInfo     │
│ - Frames        │  │ - NetworkTraffic │
│ - UI Components │  │ - PortScanner    │
└─────────────────┘  └──────────────────┘
```

### Component Interaction
1. **Frontend** creates UI components and handles user input
2. **Backend** performs actual operations (scanning, monitoring)
3. **Callbacks** connect backend events to frontend updates
4. **Threading** keeps UI responsive during long operations

## 📁 Code Structure

### File Overview

```
local-security-toolkit/
├── main.py           # Application entry point
├── backend.py        # Backend logic and data processing
├── frontend.py       # GUI components and layouts
├── README.md         # This documentation
└── requirements.txt  # Python dependencies (optional)
```

### main.py
**Purpose**: Application entry point and lifecycle management

**Key Functions**:
- `check_dependencies()`: Validates optional dependencies
- `main()`: Initializes application and handles shutdown
- Window close handling with cleanup

**Responsibilities**:
- Dependency checking and warnings
- Application initialization
- Graceful shutdown (stops active scans/captures)

### backend.py
**Purpose**: Core logic and data processing

**Classes**:

#### 1. SystemInfoBackend
```python
class SystemInfoBackend:
    def get_system_info(self) -> dict
```
- Retrieves system information using psutil
- Returns OS, CPU, memory, and uptime data
- Handles cases where psutil is unavailable

#### 2. NetworkTrafficBackend
```python
class NetworkTrafficBackend:
    def start_capture(self) -> bool
    def stop_capture(self)
    def update_filters(self, protocol_filter: str, port_filter: str)
    def _process_packet(self, packet)
    def _apply_filters(self, protocol: str, src_port: str, dst_port: str) -> bool
```
- Manages packet capture using Scapy
- Processes IPv4 and IPv6 packets
- Applies real-time filtering
- Thread-safe packet processing
- Callback-based UI updates

#### 3. PortScannerBackend
```python
class PortScannerBackend:
    def start_scan(self, target: str, start_port: int, end_port: int, timeout: float) -> bool
    def stop_scan(self)
    def validate_inputs(self, target: str, start_port: int, end_port: int, timeout: float) -> Tuple[bool, str]
    def resolve_hostname(self, target: str) -> Optional[str]
    def scan_port(self, target_ip: str, port: int, timeout: float) -> bool
    def get_service_name(self, port: int) -> str
```
- TCP port scanning functionality
- Hostname resolution
- Service identification (40+ common services)
- Input validation
- Thread-safe scanning with stop capability
- Uses context managers for proper socket cleanup

**Design Patterns in Backend**:
- **Callback Pattern**: All backend classes use callbacks to notify UI
- **Threading**: Long operations run in daemon threads
- **Resource Management**: Context managers for socket handling

### frontend.py
**Purpose**: User interface and visual components

**Classes**:

#### UI Components

**InfoCard**
- Card-style display for system information
- Title, value, and description layout
- Optional color coding for values

**MemoryProgressCard**
- Specialized card with progress bar
- Visual memory usage representation
- Color-coded alerts (green/orange/red)

**TableFrame**
- Custom table using ttk.Treeview
- Dark theme styling
- Alternating row colors
- Support for row tags and styling

#### Feature Frames

**SystemInfoFrame**
- Grid layout with info cards
- Memory progress visualization
- Refresh functionality
- Uptime color coding

**NetworkTrafficFrame**
- Control panel with filters
- Real-time packet table
- Status monitoring
- Start/stop/clear controls

**PortScannerFrame**
- Scan configuration inputs
- Progress bar
- Results table with color coding
- Real-time status updates

**AboutFrame**
- Application overview
- Feature descriptions
- Important usage notes

**MainApplication**
- Main window container
- Sidebar navigation
- Frame management
- Window centering

**UI Design Principles**:
- Dark theme (CustomTkinter)
- Consistent spacing (padding: 10-30px)
- Card-based layouts
- Color-coded status indicators
- Responsive grid layouts

## 🔧 Technical Details

### Threading Model

All long-running operations use daemon threads:

```python
thread = threading.Thread(target=self.operation, daemon=True)
thread.start()
```

**Benefits**:
- Non-blocking UI
- Automatic cleanup on exit
- Responsive user experience

### Callback Pattern

Backend classes use callbacks to update UI:

```python
# Backend registers callbacks
backend.set_callbacks(
    on_success=self.handle_success,
    on_error=self.handle_error
)

# Backend calls them when events occur
if self.on_success:
    self.on_success(data)
```

### Socket Management

Proper resource cleanup using context managers:

```python
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(timeout)
    result = sock.connect_ex((target_ip, port))
    return result == 0
```

**Benefits**:
- Automatic socket cleanup
- Exception-safe
- Prevents file descriptor leaks

### Packet Processing

Network traffic capture uses Scapy's sniff function:

```python
sniff(prn=lambda pkt: self._process_packet(pkt),
      store=False,
      stop_filter=lambda x: not self.is_capturing)
```

**Features**:
- Real-time processing
- No packet storage (memory efficient)
- Conditional stopping

## 🔒 Security Considerations

### Ethical Usage
- **Educational Purpose Only**: This tool is for learning and authorized testing
- **Permission Required**: Only test systems you own or have explicit permission to test
- **Legal Compliance**: Unauthorized scanning may violate laws and policies

### Privilege Requirements
- Network traffic capture requires administrator/root privileges
- System information and port scanning work with standard privileges

### Safety Features
- Confirmation dialogs for destructive operations
- Clear warning messages on potentially dangerous features
- Rate limiting (0.01s delay between port scans)
- Timeout protection on all network operations

### Best Practices
1. Always get written permission before scanning networks
2. Use on isolated test networks when possible
3. Respect timeout values to avoid overwhelming targets
4. Be aware of your organization's security policies
5. Log and document all security testing activities

## 🐛 Troubleshooting

### Common Issues

#### "customtkinter is required"
**Solution**: Install customtkinter
```bash
pip install customtkinter
```

#### "psutil module required for..."
**Solution**: Install psutil for system information
```bash
pip install psutil
```

#### "Scapy module required for packet capture"
**Solution**: Install scapy
```bash
pip install scapy
```

#### "Administrator/root privileges required"
**Issue**: Network traffic capture needs elevated privileges

**Solution**:
- **Linux/macOS**: Run with `sudo python main.py`
- **Windows**: Run Command Prompt as Administrator

#### Port Scanner shows no open ports
**Possible Causes**:
1. Firewall blocking connections
2. Target system is down
3. Timeout too short
4. Target has no services on scanned ports

**Solution**:
- Test with localhost (127.0.0.1) first
- Increase timeout value
- Try common ports (80, 443, 22)

#### Network capture shows no packets
**Possible Causes**:
1. No network activity
2. Wrong network interface
3. Firewall blocking capture

**Solution**:
- Generate network activity (open a website)
- Run with administrator privileges
- Check system firewall settings

### Error Messages

#### "Could not resolve hostname"
**Cause**: Invalid hostname or DNS issue  
**Solution**: Use IP address directly or check DNS settings

#### "Port numbers must be between 1 and 65535"
**Cause**: Invalid port range  
**Solution**: Enter valid port numbers

#### "Access denied"
**Cause**: Insufficient permissions  
**Solution**: Run with appropriate privileges

## 📊 Performance Considerations

### Memory Usage
- Base application: ~50-100 MB
- With packet capture: Can increase based on packet rate
- Recommendation: Clear packet display periodically for long captures

### CPU Usage
- Idle: <1%
- Port scanning: 5-15% (depends on scan range and timeout)
- Packet capture: 10-30% (depends on network traffic)

### Network Impact
- Port scanning: 0.01s delay between ports (rate limited)
- Packet capture: Passive monitoring (no traffic generated)

### Optimization Tips
1. Use appropriate timeout values (0.5-1.0s for port scans)
2. Scan smaller port ranges when possible
3. Use protocol filters in packet capture
4. Clear displays when accumulating large amounts of data

## 🛠️ Development

### Adding New Features

1. **Create Backend Class**:
```python
class NewFeatureBackend:
    def __init__(self):
        # Initialize callbacks
        self.on_result = None
    
    def perform_operation(self):
        # Your logic here
        if self.on_result:
            self.on_result(data)
```

2. **Create Frontend Frame**:
```python
class NewFeatureFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.backend = NewFeatureBackend()
        self.setup_ui()
        self.setup_callbacks()
```

3. **Register in MainApplication**:
```python
# Add to tools list
tools = ["System Info", "Network Traffic", "Port Scanner", "New Feature", "About"]

# Add frame
self.frames["New Feature"] = NewFeatureFrame(self.content_frame)
```

### Coding Standards

**Python Style**:
- Follow PEP 8
- Use type hints where appropriate
- Document all public methods
- Use descriptive variable names

**UI Consistency**:
- Maintain 15px corner radius for frames
- Use consistent padding (30px for main containers)
- Follow dark theme color scheme
- Use standard button heights (35px)

## 📝 Version History

### Version 1.0 (Current)
- Initial release
- System Information feature
- Network Traffic Analyzer
- Port Scanner
- Dark theme UI
- Fixed socket resource leak issue

## 📄 License

This project is intended for educational purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## ⚠️ Disclaimer

This tool is provided "as is" for educational purposes. The authors are not responsible for any misuse or damage caused by this software. Always ensure you have proper authorization before conducting any security testing.