# backend.py
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
    from scapy.all import sniff, IP, TCP, UDP, ICMP, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkTrafficBackend:
    """Backend for network traffic analysis"""
    
    def __init__(self):
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
        self.protocol_filter = "All"
        self.port_filter = ""
        self.selected_interface = None
        
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
    
    def get_available_interfaces(self) -> List[Tuple[str, str]]:
        """
        Get list of available network interfaces with human-readable names
        Returns: List of tuples (display_name, actual_interface_name)
        """
        if not SCAPY_AVAILABLE:
            return [("Default (Auto-detect)", None)]
        
        try:
            interfaces = []
            
            # Try to use psutil for better interface information
            if PSUTIL_AVAILABLE:
                import psutil
                net_if_addrs = psutil.net_if_addrs()
                net_if_stats = psutil.net_if_stats()
                
                for iface_name, addrs in net_if_addrs.items():
                    # Skip loopback interfaces in the list (but keep them available)
                    # Get interface status
                    is_up = net_if_stats.get(iface_name, None)
                    if is_up and not is_up.isup:
                        continue  # Skip interfaces that are down
                    
                    # Get IP address if available
                    ip_addr = None
                    for addr in addrs:
                        if addr.family == 2:  # AF_INET (IPv4)
                            ip_addr = addr.address
                            break
                    
                    # Create display name
                    if ip_addr:
                        display_name = f"{iface_name} ({ip_addr})"
                    else:
                        display_name = iface_name
                    
                    interfaces.append((display_name, iface_name))
            else:
                # Fallback to scapy's interface list
                scapy_interfaces = get_if_list()
                for iface in scapy_interfaces:
                    interfaces.append((iface, iface))
            
            # Add default option at the beginning
            interfaces.insert(0, ("Default (Auto-detect)", None))
            
            return interfaces if interfaces else [("Default (Auto-detect)", None)]
            
        except Exception as e:
            return [("Default (Auto-detect)", None)]
    
    def set_interface(self, interface: Optional[str]):
        """Set the network interface to capture on"""
        self.selected_interface = interface
    
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
            # Set interface if specified
            kwargs = {
                'prn': lambda pkt: self._process_packet(pkt),
                'store': False,
                'stop_filter': lambda x: not self.is_capturing
            }
            
            if self.selected_interface:
                kwargs['iface'] = self.selected_interface
            
            sniff(**kwargs)
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


class PortScannerBackend:
    """Backend for port scanning functionality"""
    
    def __init__(self):
        self.scanning = False
        self.scan_thread = None
        self.stop_event = threading.Event()
        
        
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
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
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


class NetworkPerformanceBackend:
    """Backend for network performance monitoring"""
    
    def __init__(self):
        self.prev_bytes_sent = 0
        self.prev_bytes_recv = 0
        self.prev_timestamp = 0.0
    
    def reset_counters(self):
        """Initialize or reset the previous counters"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            counters = psutil.net_io_counters()
            self.prev_bytes_sent = counters.bytes_sent
            self.prev_bytes_recv = counters.bytes_recv
            self.prev_timestamp = time.time()
        except Exception:
            self.prev_bytes_sent = 0
            self.prev_bytes_recv = 0
            self.prev_timestamp = time.time()
    
    def get_stats(self) -> dict:
        """
        Get current network performance statistics
        Returns: dict with upload_mbps, download_mbps, bytes_sent, bytes_recv, connections, error
        """
        if not PSUTIL_AVAILABLE:
            return {
                "upload_mbps": None,
                "download_mbps": None,
                "bytes_sent": None,
                "bytes_recv": None,
                "connections": None,
                "error": "psutil is not available"
            }
        
        try:
            # Get current counters
            current = psutil.net_io_counters()
            current_time = time.time()
            
            # Calculate deltas
            delta_bytes_sent = current.bytes_sent - self.prev_bytes_sent
            delta_bytes_recv = current.bytes_recv - self.prev_bytes_recv
            delta_time = current_time - self.prev_timestamp
            
            # Avoid division by zero
            if delta_time < 0.001:
                upload_mbps = 0.0
                download_mbps = 0.0
            else:
                # Convert to MB/s
                upload_mbps = (delta_bytes_sent / delta_time) / (1024 * 1024)
                download_mbps = (delta_bytes_recv / delta_time) / (1024 * 1024)
            
            # Get total bytes
            bytes_sent = current.bytes_sent
            bytes_recv = current.bytes_recv
            
            # Get connection count
            connections = None
            try:
                connections = len(psutil.net_connections())
            except Exception:
                # If net_connections() fails (permissions), leave as None
                pass
            
            # Update stored values
            self.prev_bytes_sent = current.bytes_sent
            self.prev_bytes_recv = current.bytes_recv
            self.prev_timestamp = current_time
            
            return {
                "upload_mbps": upload_mbps,
                "download_mbps": download_mbps,
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
                "connections": connections,
                "error": None
            }
        
        except Exception as e:
            return {
                "upload_mbps": None,
                "download_mbps": None,
                "bytes_sent": None,
                "bytes_recv": None,
                "connections": None,
                "error": str(e)
            }