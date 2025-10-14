import os
import json
import hashlib
import platform
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Callable, Tuple, Any

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class SystemInfoBackend:
    """Backend for system information retrieval"""
    
    def get_system_info(self) -> dict:
        """Get system information"""
        if not PSUTIL_AVAILABLE:
            return {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'cpu_count': 'N/A (psutil required)',
                'total_memory': 'N/A (psutil required)',
                'available_memory': 'N/A (psutil required)',
                'uptime_seconds': 'N/A (psutil required)'
            }
        
        try:
            memory = psutil.virtual_memory()
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            
            return {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'cpu_count': psutil.cpu_count(logical=True),
                'total_memory': f"{memory.total / (1024**3):.2f} GB",
                'available_memory': f"{memory.available / (1024**3):.2f} GB",
                'uptime_seconds': f"{uptime:.0f} seconds ({uptime/3600:.1f} hours)"
            }
        except Exception as e:
            return {'error': f"Error retrieving system info: {str(e)}"}


class ProcessBackend:
    """Backend for process monitoring"""
    
    def list_processes(self) -> List[dict]:
        """List running processes"""
        if not PSUTIL_AVAILABLE:
            return [{'error': 'psutil module required for process monitoring'}]
        
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info', 'cmdline']):
                try:
                    info = proc.info
                    processes.append({
                        'pid': info['pid'],
                        'name': info['name'] or 'N/A',
                        'username': info['username'] or 'N/A',
                        'cpu_percent': info['cpu_percent'] or 0.0,
                        'memory_rss': info['memory_info'].rss if info['memory_info'] else 0,
                        'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else 'N/A'
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            return [{'error': f"Error listing processes: {str(e)}"}]
        
        return processes
    
    def kill_process(self, pid: int) -> bool:
        """Attempt to kill a process by PID"""
        if not PSUTIL_AVAILABLE:
            return False
        
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            return False
        except Exception:
            return False


class NetworkBackend:
    """Backend for network connection monitoring"""
    
    def list_connections(self) -> List[dict]:
        """List network connections"""
        if not PSUTIL_AVAILABLE:
            return [{'error': 'psutil module required for network monitoring'}]
        
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                
                connections.append({
                    'local_addr': local_addr,
                    'remote_addr': remote_addr,
                    'status': conn.status or 'N/A',
                    'pid': conn.pid or 'N/A'
                })
        except (psutil.AccessDenied, PermissionError):
            return [{'error': 'Access denied. Administrator privileges may be required.'}]
        except Exception as e:
            return [{'error': f"Error listing connections: {str(e)}"}]
        
        return connections


class NetworkTrafficBackend:
    """Backend for network traffic analysis"""
    
    def __init__(self):
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
        self.protocol_filter = "All"
        self.port_filter = ""
        
        # Callback functions for UI updates
        self.on_packet_captured: Optional[Callable[[dict], None]] = None
        self.on_capture_error: Optional[Callable[[str], None]] = None
        self.on_capture_started: Optional[Callable[[], None]] = None
        self.on_capture_stopped: Optional[Callable[[], None]] = None
    
    def set_callbacks(self,
                     on_packet_captured: Optional[Callable[[dict], None]] = None,
                     on_capture_error: Optional[Callable[[str], None]] = None,
                     on_capture_started: Optional[Callable[[], None]] = None,
                     on_capture_stopped: Optional[Callable[[], None]] = None):
        """Set callback functions for UI updates"""
        self.on_packet_captured = on_packet_captured
        self.on_capture_error = on_capture_error
        self.on_capture_started = on_capture_started
        self.on_capture_stopped = on_capture_stopped
    
    def update_filters(self, protocol_filter: str, port_filter: str):
        """Update filters in real-time during capture"""
        self.protocol_filter = protocol_filter
        self.port_filter = port_filter
    
    def start_capture(self) -> bool:
        """Start capturing network packets"""
        if not SCAPY_AVAILABLE:
            if self.on_capture_error:
                self.on_capture_error("Scapy module required for packet capture")
            return False
        
        if self.is_capturing:
            return False
        
        self.is_capturing = True
        self.packet_count = 0
        
        if self.on_capture_started:
            self.on_capture_started()
        
        # Start capture in separate thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets_thread,
            daemon=True
        )
        self.capture_thread.start()
        return True
    
    def stop_capture(self):
        """Stop capturing network packets"""
        if self.is_capturing:
            self.is_capturing = False
            if self.on_capture_stopped:
                self.on_capture_stopped()
    
    def _capture_packets_thread(self):
        """Capture packets using Scapy in separate thread"""
        try:
            sniff(prn=lambda pkt: self._process_packet(pkt),
                  store=False,
                  stop_filter=lambda x: not self.is_capturing)
        except PermissionError:
            if self.on_capture_error:
                self.on_capture_error("Administrator/root privileges required to capture packets")
        except Exception as e:
            if self.on_capture_error:
                self.on_capture_error(f"Error capturing packets: {str(e)}")
    
    def _process_packet(self, packet):
        """Process and filter captured packets"""
        if not self.is_capturing:
            return
        
        try:
            src_ip = None
            dst_ip = None
            protocol = ""
            src_port = "-"
            dst_port = "-"
            packet_size = len(packet)
            
            # Check for IPv4
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if TCP in packet:
                    protocol = "TCP"
                    src_port = str(packet[TCP].sport)
                    dst_port = str(packet[TCP].dport)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = str(packet[UDP].sport)
                    dst_port = str(packet[UDP].dport)
                elif ICMP in packet:
                    protocol = "ICMP"
                else:
                    protocol = "Other"
            
            # Check for IPv6
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                
                if TCP in packet:
                    protocol = "TCP"
                    src_port = str(packet[TCP].sport)
                    dst_port = str(packet[TCP].dport)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = str(packet[UDP].sport)
                    dst_port = str(packet[UDP].dport)
                elif ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet or ICMPv6ND_NS in packet or ICMPv6ND_NA in packet:
                    protocol = "ICMP"
                else:
                    protocol = "Other"
            else:
                return
            
            if src_ip is None or dst_ip is None:
                return
            
            # Apply filters (read current filter values in real-time)
            if not self._apply_filters(protocol, src_port, dst_port):
                return
            
            # Get timestamp
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            # Create packet data dictionary
            packet_data = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'size': packet_size
            }
            
            # Notify UI
            self.packet_count += 1
            if self.on_packet_captured:
                self.on_packet_captured(packet_data)
                
        except Exception:
            pass  # Silently ignore malformed packets
    
    def _apply_filters(self, protocol: str, src_port: str, dst_port: str) -> bool:
        """Apply user-defined filters to packets"""
        # Protocol filter (read current value)
        protocol_filter_val = self.protocol_filter
        if protocol_filter_val != "All" and protocol != protocol_filter_val:
            return False
        
        # Port filter (read current value)
        port_filter_val = self.port_filter.strip()
        if port_filter_val:
            try:
                port_num = int(port_filter_val)
                if src_port != "-" and dst_port != "-":
                    if int(src_port) != port_num and int(dst_port) != port_num:
                        return False
                else:
                    return False
            except ValueError:
                pass  # Invalid port number, ignore filter
        
        return True
    
    def get_packet_count(self) -> int:
        """Get the current packet count"""
        return self.packet_count


class FileIntegrityBackend:
    """Backend for file integrity checking"""
    
    def __init__(self):
        self.baseline_file = Path.home() / '.security_toolkit_baselines.json'
        self._load_baselines()
    
    def _load_baselines(self):
        """Load baseline hashes from file"""
        try:
            if self.baseline_file.exists():
                with open(self.baseline_file, 'r') as f:
                    self.baselines = json.load(f)
            else:
                self.baselines = {}
        except Exception:
            self.baselines = {}
    
    def _save_baselines(self):
        """Save baseline hashes to file"""
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(self.baselines, f, indent=2)
        except Exception as e:
            raise Exception(f"Failed to save baselines: {str(e)}")
    
    def compute_hash(self, path: str) -> str:
        """Compute SHA256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            raise Exception(f"Failed to compute hash: {str(e)}")
    
    def save_baseline(self, key: str, path: str, hash_value: str):
        """Save baseline hash for a file"""
        self.baselines[key] = {
            'path': path,
            'hash': hash_value,
            'timestamp': datetime.now().isoformat()
        }
        self._save_baselines()
    
    def verify(self, key: str, path: str) -> Tuple[bool, str]:
        """Verify file against baseline"""
        if key not in self.baselines:
            raise Exception(f"No baseline found for key: {key}")
        
        current_hash = self.compute_hash(path)
        baseline_hash = self.baselines[key]['hash']
        
        return (current_hash == baseline_hash), current_hash


class PortScannerBackend:
    """Backend for port scanning functionality"""
    
    def __init__(self):
        self.scanning = False
        self.scan_thread = None
        self.stop_event = threading.Event()
        
        # Callback functions for UI updates
        self.on_scan_start: Optional[Callable[[], None]] = None
        self.on_scan_complete: Optional[Callable[..., None]] = None
        self.on_progress_update: Optional[Callable[[int, int, int], None]] = None
        self.on_port_result: Optional[Callable[[int, bool, str], None]] = None
        self.on_status_update: Optional[Callable[[str], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        
    def set_callbacks(self, 
                     on_scan_start: Optional[Callable[[], None]] = None,
                     on_scan_complete: Optional[Callable[..., None]] = None,
                     on_progress_update: Optional[Callable[[int, int, int], None]] = None,
                     on_port_result: Optional[Callable[[int, bool, str], None]] = None,
                     on_status_update: Optional[Callable[[str], None]] = None,
                     on_error: Optional[Callable[[str], None]] = None):
        """Set callback functions for UI updates"""
        self.on_scan_start = on_scan_start
        self.on_scan_complete = on_scan_complete
        self.on_progress_update = on_progress_update
        self.on_port_result = on_port_result
        self.on_status_update = on_status_update
        self.on_error = on_error
    
    def validate_inputs(self, target: str, start_port: int, end_port: int, timeout: float) -> Tuple[bool, str]:
        """
        Validate scan parameters
        Returns: (is_valid, error_message)
        """
        if not target.strip():
            return False, "Please enter a target IP address or hostname"
        
        if start_port < 1 or end_port < 1 or start_port > 65535 or end_port > 65535:
            return False, "Port numbers must be between 1 and 65535"
        
        if start_port > end_port:
            return False, "Start port must be less than or equal to end port"
            
        if timeout <= 0:
            return False, "Timeout must be greater than 0"
        
        return True, ""
    
    def resolve_hostname(self, target: str) -> Optional[str]:
        """
        Resolve hostname to IP address
        Returns: IP address string or None if resolution fails
        """
        try:
            ip = socket.gethostbyname(target)
            return ip
        except socket.gaierror as e:
            if self.on_error:
                self.on_error(f"Could not resolve hostname '{target}': {str(e)}")
            return None
    
    def scan_port(self, target_ip: str, port: int, timeout: float) -> bool:
        """
        Scan a single port
        Returns: True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        common_ports = {
            20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S", 587: "SMTP (TLS)",
            3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL", 1433: "MSSQL",
            6379: "Redis", 27017: "MongoDB", 8080: "HTTP Alt", 8443: "HTTPS Alt",
            135: "RPC", 139: "NetBIOS", 445: "SMB", 161: "SNMP", 162: "SNMP Trap",
            389: "LDAP", 636: "LDAPS", 1521: "Oracle", 5060: "SIP", 5061: "SIP-TLS",
            69: "TFTP", 123: "NTP", 179: "BGP", 514: "Syslog", 1723: "PPTP",
            1194: "OpenVPN", 8000: "HTTP Alt", 9000: "Web Alt"
        }
        return common_ports.get(port, "Unknown")
    
    def get_scan_statistics(self, open_ports: List[int], closed_ports: List[int], 
                          duration: float) -> Dict:
        """Generate scan statistics"""
        return {
            'total_ports': len(open_ports) + len(closed_ports),
            'open_ports': len(open_ports),
            'closed_ports': len(closed_ports),
            'duration': duration,
            'open_port_list': open_ports
        }
    
    def scan_ports_thread(self, target: str, start_port: int, end_port: int, timeout: float):
        """Main scanning thread function"""
        try:
            self.stop_event.clear()
            
            # Validate inputs
            is_valid, error_msg = self.validate_inputs(target, start_port, end_port, timeout)
            if not is_valid:
                if self.on_error:
                    self.on_error(error_msg)
                return
            
            # Notify scan start
            if self.on_scan_start:
                self.on_scan_start()
            
            # Update status
            if self.on_status_update:
                self.on_status_update("Resolving hostname...")
            
            # Resolve hostname to IP
            target_ip = self.resolve_hostname(target)
            if not target_ip:
                return
            
            # Initialize scan variables
            total_ports = end_port - start_port + 1
            open_ports = []
            closed_ports = []
            
            start_time = datetime.now()
            
            # Update status
            if self.on_status_update:
                self.on_status_update(f"Scanning {target_ip} ({total_ports} ports)")
            
            # Scan each port
            for i, port in enumerate(range(start_port, end_port + 1)):
                if self.stop_event.is_set():
                    break
                
                # Update progress
                progress = i + 1
                if self.on_progress_update:
                    self.on_progress_update(progress, total_ports, port)
                
                # Scan the port
                is_open = self.scan_port(target_ip, port, timeout)
                service = self.get_service_name(port)
                
                # Store results
                if is_open:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
                
                # Notify UI of port result
                if self.on_port_result:
                    self.on_port_result(port, is_open, service)
                
                # Small delay to prevent overwhelming the target
                time.sleep(0.01)
            
            # Calculate scan duration
            end_time = datetime.now()
            duration = end_time - start_time
            
            # Generate statistics
            stats = self.get_scan_statistics(open_ports, closed_ports, duration.total_seconds())
            
            # Notify scan completion
            if self.on_scan_complete:
                self.on_scan_complete(stats, target_ip, not self.stop_event.is_set())
                
        except Exception as e:
            if self.on_error:
                self.on_error(f"Scan error: {str(e)}")
        finally:
            self.scanning = False
    
    def start_scan(self, target: str, start_port: int, end_port: int, timeout: float) -> bool:
        """
        Start port scanning process
        Returns: True if scan started successfully, False otherwise
        """
        if self.scanning:
            return False
        
        self.scanning = True
        
        # Start scanning thread
        self.scan_thread = threading.Thread(
            target=self.scan_ports_thread,
            args=(target, start_port, end_port, timeout)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        return True
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning:
            self.stop_event.set()
            if self.on_status_update:
                self.on_status_update("Stopping scan...")
            
            # Wait for thread to complete
            if self.scan_thread and self.scan_thread.is_alive():
                self.scan_thread.join(timeout=2.0)
            
            self.scanning = False
    
    def is_scanning(self) -> bool:
        """Check if a scan is currently in progress"""
        return self.scanning


class ScanResult:
    """Data class for scan results"""
    def __init__(self, port: int, is_open: bool, service: str, timestamp: datetime = None):
        self.port = port
        self.is_open = is_open
        self.service = service
        self.timestamp = timestamp or datetime.now()
    
    def __str__(self):
        status = "OPEN" if self.is_open else "CLOSED"
        return f"Port {self.port:5d}: {status:6s} - {self.service}"


class ScanSession:
    """Class to manage scan session data"""
    def __init__(self):
        self.target = ""
        self.target_ip = ""
        self.start_port = 0
        self.end_port = 0
        self.timeout = 0.0
        self.results: List[ScanResult] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.completed = False
    
    def add_result(self, result: ScanResult):
        """Add a scan result to the session"""
        self.results.append(result)
    
    def get_open_ports(self) -> List[int]:
        """Get list of open ports"""
        return [r.port for r in self.results if r.is_open]
    
    def get_closed_ports(self) -> List[int]:
        """Get list of closed ports"""
        return [r.port for r in self.results if not r.is_open]
    
    def get_duration(self) -> float:
        """Get scan duration in seconds"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0