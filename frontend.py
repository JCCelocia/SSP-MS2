# frontend.py
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
import threading
import tkinter.messagebox as msgbox
from typing import Optional

from backend import (
    PortScannerBackend, NetworkTrafficBackend, NetworkPerformanceBackend
)


class TableFrame(ctk.CTkFrame):
    """Custom table using ttk.Treeview with dark theme styling"""
    
    def __init__(self, parent, columns, show_headers=True):
        super().__init__(parent, corner_radius=10)
        self.columns = columns
                
        style = ttk.Style()
        style.theme_use("clam")
                
        style.configure("Treeview",
                       background="#2b2b2b",
                       foreground="white",
                       fieldbackground="#2b2b2b",
                       borderwidth=0)
        style.configure("Treeview.Heading",
                       background="#1f538d",
                       foreground="white",
                       borderwidth=1,
                       relief="flat")
        style.map("Treeview.Heading",
                 background=[('active', '#14375e')])
        style.map("Treeview",
                 background=[('selected', '#0078d4')])
        
        # Create treeview with scrollbar
        tree_frame = ctk.CTkFrame(self, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Treeview
        self.tree = ttk.Treeview(tree_frame, columns=list(columns.keys()), 
                                show='headings' if show_headers else '')
        
        # Configure columns
        for col_id, (header, width) in columns.items():
            if show_headers:
                self.tree.heading(col_id, text=header, anchor='w')
            self.tree.column(col_id, width=width, anchor='w')
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def clear(self):
        """Clear all items from the table"""
        for item in self.tree.get_children():
            self.tree.delete(item)
    
    def insert(self, values, tags=None):
        """Insert a row into the table"""
        self.tree.insert("", "end", values=values, tags=tags or ())
    
    def configure_tags(self, tag_configs):
        """Configure tags for row styling"""
        for tag, config in tag_configs.items():
            self.tree.tag_configure(tag, **config)


class NetworkTrafficFrame(ctk.CTkFrame):
    """Network Traffic Analyzer Frame"""
    
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.backend = NetworkTrafficBackend()
        self.interface_mapping = {}  # Maps display names to actual interface names
        self.all_packets = []  # master list of dicts from backend
        self.search_var = tk.StringVar(value="")
        self.setup_ui()
        self.setup_callbacks()
        self.load_interfaces()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
               
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))
        
        title = ctk.CTkLabel(header_frame, text="Network Traffic Analyzer", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(side="left")
        
        subtitle = ctk.CTkLabel(header_frame, text="Capture and analyze network packets in real-time", 
                              font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        subtitle.pack(side="left", padx=(15, 0), anchor="s")
                
        warning = ctk.CTkLabel(main_container, text="⚠️ Requires administrator/root privileges • Only capture on networks you own or have permission to monitor", 
                              text_color="orange", font=ctk.CTkFont(size=12, weight="bold"))
        warning.pack(pady=(0, 15))
                
        self.create_controls(main_container)
                
        self.create_status_section(main_container)
            
        self.create_packet_table(main_container)
    
    def create_controls(self, parent):
        """Create control section"""
        controls_section = ctk.CTkFrame(parent, corner_radius=10)
        controls_section.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(controls_section, text="Capture Controls", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        # Interface selection row
        interface_row = ctk.CTkFrame(controls_section, fg_color="transparent")
        interface_row.pack(pady=(0, 10))
        
        ctk.CTkLabel(interface_row, text="Network Interface:", 
                    font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=(20, 5))
        self.interface_var = tk.StringVar(value="Default (Auto-detect)")
        self.interface_dropdown = ctk.CTkOptionMenu(interface_row, variable=self.interface_var,
                                                    values=["Default (Auto-detect)"], width=300,
                                                    command=self.on_interface_changed)
        self.interface_dropdown.pack(side="left", padx=(0, 10))
        
        refresh_interfaces_btn = ctk.CTkButton(interface_row, text="↻ Refresh", width=80, height=28,
                                              command=self.load_interfaces,
                                              font=ctk.CTkFont(size=12))
        refresh_interfaces_btn.pack(side="left", padx=(0, 10))
        
        # Add helpful hint
        hint_label = ctk.CTkLabel(interface_row, text="💡 Select the network adapter to monitor",
                                 font=ctk.CTkFont(size=11), text_color=("gray50", "gray50"))
        hint_label.pack(side="left", padx=(10, 0))
        
        # Filter row
        filter_row = ctk.CTkFrame(controls_section, fg_color="transparent")
        filter_row.pack(pady=(0, 10))
        
        ctk.CTkLabel(filter_row, text="Protocol:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(20, 5))
        self.protocol_var = tk.StringVar(value="All")
        protocol_dropdown = ctk.CTkOptionMenu(filter_row, variable=self.protocol_var,
                                            values=["All", "TCP", "UDP", "ICMP"], width=100)
        protocol_dropdown.pack(side="left", padx=(0, 20))
        
        ctk.CTkLabel(filter_row, text="Port:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 5))
        self.port_entry = ctk.CTkEntry(filter_row, width=80, placeholder_text="80")
        self.port_entry.pack(side="left")
        
        # Bind live changes to backend filters
        self.protocol_var.trace_add("write", lambda *_: self.on_filter_changed())
        self.port_entry.bind("<KeyRelease>", lambda _e: self.on_filter_changed())
        
        # Search row
        search_row = ctk.CTkFrame(controls_section, fg_color="transparent")
        search_row.pack(pady=(0, 10))
        
        ctk.CTkLabel(search_row, text="Search:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(20, 5))
        self.search_entry = ctk.CTkEntry(search_row, width=240, textvariable=self.search_var, placeholder_text="ip, protocol, port…  (e.g., tcp or src:192.168 or dport:443)")
        self.search_entry.pack(side="left")
        
        # Info ("?") button for search help
        info_btn = ctk.CTkButton(
            search_row,
            text="?",
            width=28,
            height=28,
            fg_color="#3B8ED0",
            hover_color="#1F6AA5",
            command=self.show_search_help,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        info_btn.pack(side="left", padx=(8, 0))
        
        # react to typing
        self.search_var.trace_add("write", lambda *_: self.refresh_table())
        
        # Button row
        button_row = ctk.CTkFrame(controls_section, fg_color="transparent")
        button_row.pack(pady=(0, 15))
        
        self.start_btn = ctk.CTkButton(button_row, text="Start Capture", command=self.start_capture,
                                      fg_color="green", hover_color="darkgreen", height=35, width=130)
        self.start_btn.pack(side="left", padx=(20, 10))
        
        self.stop_btn = ctk.CTkButton(button_row, text="Stop Capture", command=self.stop_capture,
                                     fg_color="red", hover_color="darkred", state="disabled", height=35, width=130)
        self.stop_btn.pack(side="left", padx=(0, 10))
        
        self.clear_btn = ctk.CTkButton(button_row, text="Clear Display", command=self.clear_display,
                                      height=35, width=130)
        self.clear_btn.pack(side="left")
    
    def create_status_section(self, parent):
        """Create status display section"""
        status_section = ctk.CTkFrame(parent, corner_radius=10)
        status_section.pack(fill="x", pady=(0, 15))
        
        status_inner = ctk.CTkFrame(status_section, fg_color="transparent")
        status_inner.pack(fill="x", padx=20, pady=15)
        
        self.status_label = ctk.CTkLabel(status_inner, text="✅ Ready to capture - Select interface and click Start",
                                        font=ctk.CTkFont(size=12), text_color=("gray60", "gray40"))
        self.status_label.pack(side="left")
        
        self.packet_count_label = ctk.CTkLabel(status_inner, text="Packets: 0",
                                              font=ctk.CTkFont(size=12, weight="bold"))
        self.packet_count_label.pack(side="right")
    
    def create_packet_table(self, parent):
        """Create packet display table"""
        table_frame = ctk.CTkFrame(parent, corner_radius=10)
        table_frame.pack(fill="both", expand=True)
        
        header_label = ctk.CTkLabel(table_frame, text="Captured Packets", 
                                  font=ctk.CTkFont(size=16, weight="bold"))
        header_label.pack(pady=(15, 10))
                
        columns = {
            'time': ('Timestamp', 120),
            'src_ip': ('Source IP', 140),
            'dst_ip': ('Destination IP', 140),
            'protocol': ('Protocol', 80),
            'src_port': ('Src Port', 80),
            'dst_port': ('Dst Port', 80),
            'size': ('Size (bytes)', 100)
        }
        
        self.packet_table = TableFrame(table_frame, columns)
        self.packet_table.pack(fill="both", expand=True, padx=15, pady=(0, 15))
                
        self.packet_table.configure_tags({
            'evenrow': {'background': '#363636'},
            'oddrow': {'background': '#2b2b2b'}
        })
    
    def load_interfaces(self):
        """Load available network interfaces"""
        interfaces_data = self.backend.get_available_interfaces()
        
        # Clear the mapping
        self.interface_mapping.clear()
        
        # Extract display names and create mapping
        display_names = []
        for display_name, actual_name in interfaces_data:
            display_names.append(display_name)
            self.interface_mapping[display_name] = actual_name
        
        # Update dropdown
        if display_names:
            self.interface_dropdown.configure(values=display_names)
            # Set to first interface (Default)
            self.interface_var.set(display_names[0])
            # Set backend interface
            self.backend.set_interface(self.interface_mapping[display_names[0]])
            self.status_label.configure(text=f"Interface: {display_names[0]}")
        else:
            self.interface_dropdown.configure(values=["Default (Auto-detect)"])
            self.interface_var.set("Default (Auto-detect)")
            self.backend.set_interface(None)
    
    def on_interface_changed(self, display_name):
        """Called when interface selection changes"""
        # Get actual interface name from mapping
        actual_interface = self.interface_mapping.get(display_name, None)
        self.backend.set_interface(actual_interface)
        self.status_label.configure(text=f"Interface: {display_name}")
    
    def show_search_help(self):
        """Show popup explaining search syntax"""
        msg = (
            "🔍 How to Use Search\n\n"
            "• Type any word to search across all packet details.\n"
            "  Example: tcp, udp, 192.168\n\n"
            "• Use field filters:\n"
            "  src:<ip>    → filter by source IP\n"
            "  dst:<ip>    → filter by destination IP\n"
            "  sport:<num> → source port\n"
            "  dport:<num> → destination port\n\n"
            "• Use comparisons:\n"
            "  size>500 → packets larger than 500 bytes\n"
            "  size<200 → packets smaller than 200 bytes\n"
            "  size:1-100 → packets between that range\n\n"
            "• Combining filters:\n"
            "  You can type several filters together — just separate them with spaces.\n"
            "  Don't use commas or punctuation between filters.\n"
            "  Example:\n"
            "  tcp dport:443 size:100-300\n"
            "  (shows TCP packets going to port 443 and between 100–300 bytes)\n\n"
            "  You can also combine IP and port filters like:\n"
            "  src:192.168.1.5 dport:80 size>200\n"
            "  (shows packets from 192.168.1.5 going to port 80 that are larger than 200 bytes)\n\n"
            "💡 Tip: You can keep typing while capturing — the display updates instantly!"
        )
        msgbox.showinfo("Search Help", msg)
    
    def packet_matches_query(self, pkt: dict, q: str) -> bool:
        """
        Simple query language:
          - plain text matches any column (case-insensitive)
          - key:value matches a specific field (keys: src, dst, proto, sport, dport, size)
        Examples: 'tcp', 'src:192.168', 'dport:53', 'size>500'
        """
        if not q:
            return True

        q = q.strip().lower()
        tokens = q.split()

        # build a lowercase view of fields
        fields = {
            "time": pkt["timestamp"].lower(),
            "src": pkt["src_ip"].lower(),
            "dst": pkt["dst_ip"].lower(),
            "proto": pkt["protocol"].lower(),
            "sport": pkt["src_port"].lower(),
            "dport": pkt["dst_port"].lower(),
            "size": str(pkt["size"]).lower(),
            # everything concatenated for loose text matches
            "_all": " ".join([
                pkt["timestamp"], pkt["src_ip"], pkt["dst_ip"],
                pkt["protocol"], pkt["src_port"], pkt["dst_port"],
                str(pkt["size"])
            ]).lower()
        }

        def match_token(tok: str) -> bool:
            # key:value
            if ":" in tok:
                key, val = tok.split(":", 1)
                key = key.strip()
                val = val.strip()
                
                # Handle size range (size:X-Y)
                if key == "size" and "-" in val:
                    try:
                        min_size, max_size = val.split("-", 1)
                        packet_size = int(fields["size"])
                        return int(min_size) <= packet_size <= int(max_size)
                    except:
                        return False
                
                if key in fields:
                    return val in fields[key]
                return val in fields["_all"]

            # numeric comparisons on size
            if tok.startswith("size>"):
                try:
                    return int(fields["size"]) > int(tok[5:])
                except:
                    return False
            if tok.startswith("size<"):
                try:
                    return int(fields["size"]) < int(tok[5:])
                except:
                    return False

            # plain substring over any column
            return tok in fields["_all"]

        # AND over tokens
        return all(match_token(t) for t in tokens)

    def refresh_table(self):
        """Rebuild table from self.all_packets using current search."""
        self.packet_table.clear()
        query = self.search_var.get()
        count = 0
        for pkt in self.all_packets:
            if self.packet_matches_query(pkt, query):
                tag = 'evenrow' if count % 2 == 0 else 'oddrow'
                self.packet_table.insert([
                    pkt['timestamp'], pkt['src_ip'], pkt['dst_ip'], pkt['protocol'],
                    pkt['src_port'], pkt['dst_port'], str(pkt['size'])
                ], tags=[tag])
                count += 1
        # keep the "Packets:" counter tied to total captured (unchanged)
        self.packet_count_label.configure(text=f"Packets: {self.backend.get_packet_count()}")
    
    def setup_callbacks(self):
        """Setup backend callbacks"""
        self.backend.set_callbacks(
            on_packet_captured=self.on_packet_captured,
            on_capture_error=self.on_capture_error,
            on_capture_started=self.on_capture_started,
            on_capture_stopped=self.on_capture_stopped
        )
    
    def on_filter_changed(self):
        """Called when filter values change - update backend filters in real-time"""
        protocol_filter = self.protocol_var.get()
        port_filter = self.port_entry.get().strip()
        self.backend.update_filters(protocol_filter, port_filter)
    
    def start_capture(self):
        """Start packet capture"""
        # Set initial filter values
        self.on_filter_changed()
        
        # Start capture without passing filters
        if self.backend.start_capture():
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.interface_dropdown.configure(state="disabled")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.backend.stop_capture()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.interface_dropdown.configure(state="normal")
    
    def clear_display(self):
        """Clear packet display"""
        self.packet_table.clear()
        self.all_packets = []  # reset stored packets
        self.backend.packet_count = 0
        self.packet_count_label.configure(text="Packets: 0")
        self.status_label.configure(text="✨ Display cleared - Ready to capture")
    
    # Callback methods
    def on_packet_captured(self, packet_data):
        """Called when a packet is captured"""
        self.all_packets.append(packet_data)

        def update_ui():
            count_total = self.backend.get_packet_count()
            self.packet_count_label.configure(text=f"Packets: {count_total}")

            # insert only if it matches current query; otherwise just keep it in all_packets
            if self.packet_matches_query(packet_data, self.search_var.get()):
                # compute row index among currently displayed rows for striping
                displayed_rows = len(self.packet_table.tree.get_children())
                tag = 'evenrow' if displayed_rows % 2 == 0 else 'oddrow'

                self.packet_table.insert([
                    packet_data['timestamp'],
                    packet_data['src_ip'],
                    packet_data['dst_ip'],
                    packet_data['protocol'],
                    packet_data['src_port'],
                    packet_data['dst_port'],
                    str(packet_data['size'])
                ], tags=[tag])

                # Auto-scroll to bottom
                children = self.packet_table.tree.get_children()
                if children:
                    self.packet_table.tree.yview_moveto(1)

        self.after(0, update_ui)
    
    def on_capture_error(self, error_msg):
        """Called when a capture error occurs"""
        self.after(0, lambda: msgbox.showerror("Capture Error", error_msg))
        self.after(0, lambda: [
            self.start_btn.configure(state="normal"),
            self.stop_btn.configure(state="disabled"),
            self.interface_dropdown.configure(state="normal")
        ])
    
    def on_capture_started(self):
        """Called when capture starts"""
        display_name = self.interface_var.get()
        self.after(0, lambda: self.status_label.configure(text=f"📡 Capturing on {display_name}..."))
    
    def on_capture_stopped(self):
        """Called when capture stops"""
        self.after(0, lambda: self.status_label.configure(text="⏸️ Capture stopped"))


class PortScannerFrame(ctk.CTkFrame):
    """Port Scanner Frame"""
    
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.backend = PortScannerBackend()
        self.setup_ui()
        self.setup_callbacks()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Header section
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))
        
        title = ctk.CTkLabel(header_frame, text="Port Scanner", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(side="left")
        
        subtitle = ctk.CTkLabel(header_frame, text="Check which services are open on a target system", 
                              font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        subtitle.pack(side="left", padx=(15, 0), anchor="s")
        
        
        warning = ctk.CTkLabel(main_container, text="⚠️ Only scan systems you own or have permission to test", 
                              text_color="orange", font=ctk.CTkFont(size=12, weight="bold"))
        warning.pack(pady=(0, 15))
                
        self.create_scan_controls(main_container)
                
        self.create_progress_section(main_container)
                
        self.create_results_section(main_container)
    
    def create_scan_controls(self, parent):
        """Create scan input and control section"""
        controls_section = ctk.CTkFrame(parent, corner_radius=10)
        controls_section.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(controls_section, text="Scan Settings", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        # Input row
        input_row = ctk.CTkFrame(controls_section, fg_color="transparent")
        input_row.pack(pady=(0, 10))
        
        ctk.CTkLabel(input_row, text="Target:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(20, 5))
        self.target_entry = ctk.CTkEntry(input_row, width=150, placeholder_text="127.0.0.1")
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.pack(side="left", padx=(0, 15))
        
        ctk.CTkLabel(input_row, text="Start Port:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 5))
        self.start_port_entry = ctk.CTkEntry(input_row, width=80)
        self.start_port_entry.insert(0, "20")
        self.start_port_entry.pack(side="left", padx=(0, 15))
        
        ctk.CTkLabel(input_row, text="End Port:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 5))
        self.end_port_entry = ctk.CTkEntry(input_row, width=80)
        self.end_port_entry.insert(0, "1024")
        self.end_port_entry.pack(side="left", padx=(0, 15))
        
        ctk.CTkLabel(input_row, text="Timeout:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 5))
        self.timeout_entry = ctk.CTkEntry(input_row, width=60)
        self.timeout_entry.insert(0, "0.5")
        self.timeout_entry.pack(side="left")
        
        # Button row
        button_row = ctk.CTkFrame(controls_section, fg_color="transparent")
        button_row.pack(pady=(0, 15))
        
        self.start_btn = ctk.CTkButton(button_row, text="Start Scan", command=self.start_scan, 
                                      fg_color="green", hover_color="darkgreen", height=35, width=120)
        self.start_btn.pack(side="left", padx=(20, 10))
        
        self.stop_btn = ctk.CTkButton(button_row, text="Stop Scan", command=self.stop_scan, 
                                     fg_color="red", hover_color="darkred", state="disabled", height=35, width=120)
        self.stop_btn.pack(side="left", padx=(0, 10))
        
        self.clear_btn = ctk.CTkButton(button_row, text="Clear Results", command=self.clear_results,
                                     height=35, width=120)
        self.clear_btn.pack(side="left")
    
    def create_progress_section(self, parent):
        """Create progress display section"""
        progress_section = ctk.CTkFrame(parent, corner_radius=10)
        progress_section.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(progress_section, text="Scan Progress", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        self.progress_bar = ctk.CTkProgressBar(progress_section)
        self.progress_bar.pack(fill="x", padx=20, pady=(0, 10))
        self.progress_bar.set(0)
        
        self.status_label = ctk.CTkLabel(progress_section, text="Ready to scan",
                                       font=ctk.CTkFont(size=12), text_color=("gray60", "gray40"))
        self.status_label.pack(pady=(0, 15))
    
    def create_results_section(self, parent):
        """Create results display section"""
        results_section = ctk.CTkFrame(parent, corner_radius=10)
        results_section.pack(fill="both", expand=True)
        
        ctk.CTkLabel(results_section, text="Scan Results", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        # Results table
        columns = {
            'port': ('Port', 80),
            'status': ('Status', 100),
            'service': ('Service', 150),
            'details': ('Details', 200)
        }
        
        self.results_table = TableFrame(results_section, columns)
        self.results_table.pack(fill="both", expand=True, padx=15, pady=(0, 15))
                
        self.results_table.configure_tags({
            'open': {'background': '#1a5d1a', 'foreground': 'lightgreen'},
            'closed': {'background': '#2b2b2b', 'foreground': 'gray'},
            'info': {'background': '#1a4d5d', 'foreground': 'lightblue'}
        })
    
    def setup_callbacks(self):
        """Setup backend callbacks"""
        self.backend.set_callbacks(
            on_scan_start=self.on_scan_start,
            on_scan_complete=self.on_scan_complete,
            on_progress_update=self.on_progress_update,
            on_port_result=self.on_port_result,
            on_status_update=self.on_status_update,
            on_error=self.on_error
        )
    
    def start_scan(self):
        """Start port scan"""
        try:
            target = self.target_entry.get().strip()
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            timeout = float(self.timeout_entry.get())
            
            # Clear previous results
            self.results_table.clear()
            
            if self.backend.start_scan(target, start_port, end_port, timeout):
                self.start_btn.configure(state="disabled")
                self.stop_btn.configure(state="normal")
            
        except ValueError:
            msgbox.showerror("Error", "Please check your input values")
        except Exception as e:
            msgbox.showerror("Error", f"Failed to start scan: {str(e)}")
    
    def stop_scan(self):
        """Stop port scan"""
        self.backend.stop_scan()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
    
    def clear_results(self):
        """Clear scan results"""
        self.results_table.clear()
        self.progress_bar.set(0)
        self.status_label.configure(text="Ready to scan")
    
    # Callback methods
    def on_scan_start(self):
        """Called when scan starts"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.after(0, lambda: self.results_table.insert(
            ["-", "STARTED", f"Scan started at {timestamp}", "-"], tags=['info']))
    
    def on_scan_complete(self, stats, target_ip, completed):
        """Called when scan completes"""
        def update_ui():
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")
            status = "COMPLETED" if completed else "STOPPED"
            details = f"{stats['open_ports']} open ports found in {stats['duration']:.1f}s"
            
            self.results_table.insert(["-", status, f"Scan finished at {timestamp}", details], tags=['info'])
            
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.progress_bar.set(0)
            self.status_label.configure(text=f"Scan {status.lower()}")
        
        self.after(0, update_ui)
    
    def on_progress_update(self, current, total, port):
        """Called on progress update"""
        def update_ui():
            progress = current / total if total > 0 else 0
            self.progress_bar.set(progress)
            self.status_label.configure(text=f"Scanning port {port} ({current}/{total})")
        
        self.after(0, update_ui)
    
    def on_port_result(self, port, is_open, service):
        """Called when a port result is available"""
        def update_ui():
            status = "OPEN" if is_open else "CLOSED"
            tag = 'open' if is_open else 'closed'
            
            # Only show open ports in table to avoid clutter
            if is_open:
                self.results_table.insert([str(port), status, service, "Service detected"], tags=[tag])
        
        self.after(0, update_ui)
    
    def on_status_update(self, status):
        """Called on status update"""
        self.after(0, lambda: self.status_label.configure(text=status))
    
    def on_error(self, error):
        """Called on error"""
        self.after(0, lambda: msgbox.showerror("Scan Error", error))


class NetworkPerformanceFrame(ctk.CTkFrame):
    """Network Performance Monitor Frame"""
    
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.backend = NetworkPerformanceBackend()
        self.updating = False
        self.setup_ui()
        self.backend.reset_counters()
        self.start_updates()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Header section
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))
        
        title = ctk.CTkLabel(header_frame, text="Network Performance Monitor", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(side="left")
        
        subtitle = ctk.CTkLabel(header_frame, text="Real-time upload/download speed and connection overview", 
                              font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        subtitle.pack(side="left", padx=(15, 0), anchor="s")
        
        # Speed section
        speed_section = ctk.CTkFrame(main_container, corner_radius=10)
        speed_section.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(speed_section, text="Network Speed", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 20))
        
        # Upload speed
        upload_frame = ctk.CTkFrame(speed_section, fg_color="transparent")
        upload_frame.pack(fill="x", padx=30, pady=(0, 15))
        
        ctk.CTkLabel(upload_frame, text="Upload Speed:", 
                   font=ctk.CTkFont(size=14)).pack(side="left")
        self.upload_label = ctk.CTkLabel(upload_frame, text="0.00 MB/s", 
                                        font=ctk.CTkFont(size=24, weight="bold"),
                                        text_color=("#3B8ED0", "#1F6AA5"))
        self.upload_label.pack(side="left", padx=(10, 0))
        
        # Download speed
        download_frame = ctk.CTkFrame(speed_section, fg_color="transparent")
        download_frame.pack(fill="x", padx=30, pady=(0, 20))
        
        ctk.CTkLabel(download_frame, text="Download Speed:", 
                   font=ctk.CTkFont(size=14)).pack(side="left")
        self.download_label = ctk.CTkLabel(download_frame, text="0.00 MB/s", 
                                          font=ctk.CTkFont(size=24, weight="bold"),
                                          text_color=("#3B8ED0", "#1F6AA5"))
        self.download_label.pack(side="left", padx=(10, 0))
        
        # Totals section
        totals_section = ctk.CTkFrame(main_container, corner_radius=10)
        totals_section.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(totals_section, text="Total Data Transfer", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 20))
        
        # Bytes sent
        sent_frame = ctk.CTkFrame(totals_section, fg_color="transparent")
        sent_frame.pack(fill="x", padx=30, pady=(0, 10))
        
        ctk.CTkLabel(sent_frame, text="Bytes Sent:", 
                   font=ctk.CTkFont(size=12)).pack(side="left")
        self.sent_label = ctk.CTkLabel(sent_frame, text="0", 
                                      font=ctk.CTkFont(size=14))
        self.sent_label.pack(side="left", padx=(10, 0))
        
        # Bytes received
        recv_frame = ctk.CTkFrame(totals_section, fg_color="transparent")
        recv_frame.pack(fill="x", padx=30, pady=(0, 20))
        
        ctk.CTkLabel(recv_frame, text="Bytes Received:", 
                   font=ctk.CTkFont(size=12)).pack(side="left")
        self.recv_label = ctk.CTkLabel(recv_frame, text="0", 
                                      font=ctk.CTkFont(size=14))
        self.recv_label.pack(side="left", padx=(10, 0))
        
        # Connections section
        connections_section = ctk.CTkFrame(main_container, corner_radius=10)
        connections_section.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(connections_section, text="Network Connections", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 20))
        
        conn_frame = ctk.CTkFrame(connections_section, fg_color="transparent")
        conn_frame.pack(fill="x", padx=30, pady=(0, 20))
        
        ctk.CTkLabel(conn_frame, text="Active Connections:", 
                   font=ctk.CTkFont(size=12)).pack(side="left")
        self.connections_label = ctk.CTkLabel(conn_frame, text="0", 
                                             font=ctk.CTkFont(size=14))
        self.connections_label.pack(side="left", padx=(10, 0))
        
        # Error message label (hidden by default)
        self.error_label = ctk.CTkLabel(main_container, text="", 
                                       text_color="orange",
                                       font=ctk.CTkFont(size=12, weight="bold"))
        self.error_label.pack(pady=(10, 0))
    
    def start_updates(self):
        """Start the update cycle"""
        self.updating = True
        self.backend.reset_counters()
        self.schedule_update()
    
    def schedule_update(self):
        """Schedule the next update"""
        if self.updating:
            self.update_stats()
            self.after(1000, self.schedule_update)
    
    def update_stats(self):
        """Update statistics from backend"""
        stats = self.backend.get_stats()
        
        if stats["error"]:
            # Show error message
            self.error_label.configure(text=f"⚠️ {stats['error']}")
            self.upload_label.configure(text="N/A")
            self.download_label.configure(text="N/A")
            self.sent_label.configure(text="N/A")
            self.recv_label.configure(text="N/A")
            self.connections_label.configure(text="N/A")
        else:
            # Clear error message
            self.error_label.configure(text="")
            
            # Update speeds
            if stats["upload_mbps"] is not None:
                self.upload_label.configure(text=f"{stats['upload_mbps']:.2f} MB/s")
            else:
                self.upload_label.configure(text="N/A")
            
            if stats["download_mbps"] is not None:
                self.download_label.configure(text=f"{stats['download_mbps']:.2f} MB/s")
            else:
                self.download_label.configure(text="N/A")
            
            # Update totals
            if stats["bytes_sent"] is not None:
                self.sent_label.configure(text=f"{stats['bytes_sent']:,}")
            else:
                self.sent_label.configure(text="N/A")
            
            if stats["bytes_recv"] is not None:
                self.recv_label.configure(text=f"{stats['bytes_recv']:,}")
            else:
                self.recv_label.configure(text="N/A")
            
            # Update connections
            if stats["connections"] is not None:
                self.connections_label.configure(text=str(stats["connections"]))
            else:
                self.connections_label.configure(text="N/A")
    
    def destroy(self):
        """Stop updates when frame is destroyed"""
        self.updating = False
        super().destroy()


class MainApplication(ctk.CTk):
    """Main Application Window"""
    
    def __init__(self):
        super().__init__()
                
        self.title("Local Security Toolkit")
        self.geometry("1200x900")
                
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
                
        self.setup_ui()
                
        self.center_window()
                
        # Show Network Traffic screen by default
        self.show_frame("Network Traffic")
    
    def center_window(self):
        """Center the window on screen"""
        self.update_idletasks()
        width = 1200
        height = 900
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_ui(self):
        """Setup the main UI"""
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
                
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(4, weight=1)
                
        sidebar_title = ctk.CTkLabel(self.sidebar, text="Security Toolkit", 
                                   font=ctk.CTkFont(size=20, weight="bold"))
        sidebar_title.grid(row=0, column=0, padx=20, pady=(30, 20))
                
        self.sidebar_buttons = {}
        tools = [
            "Network Traffic",
            "Port Scanner",
            "Network Performance"
        ]
        
        for i, tool in enumerate(tools, 1):
            btn = ctk.CTkButton(self.sidebar, text=tool, 
                               command=lambda t=tool: self.show_frame(t),
                               width=200, height=45, font=ctk.CTkFont(size=14),
                               anchor="center")
            btn.grid(row=i, column=0, padx=10, pady=8)
            self.sidebar_buttons[tool] = btn
                
        self.content_frame = ctk.CTkFrame(self, corner_radius=0)
        self.content_frame.grid(row=0, column=1, sticky="nsew")
                
        self.frames = {}
        self.frames["Network Traffic"] = NetworkTrafficFrame(self.content_frame)
        self.frames["Port Scanner"] = PortScannerFrame(self.content_frame)
        self.frames["Network Performance"] = NetworkPerformanceFrame(self.content_frame)
                
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
    
    def show_frame(self, frame_name):
        """Show the selected frame"""
        
        for frame in self.frames.values():
            frame.grid_remove()
                
        if frame_name in self.frames:
            self.frames[frame_name].grid(row=0, column=0, sticky="nsew")
                
        for name, btn in self.sidebar_buttons.items():
            if name == frame_name:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color=["#3B8ED0", "#1F6AA5"])