import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
import threading
import tkinter.messagebox as msgbox
from typing import Optional

from backend import (
    SystemInfoBackend, PortScannerBackend, NetworkTrafficBackend
)


class WelcomeFrame(ctk.CTkFrame):
    """Welcome/Main Menu Frame"""
    
    def __init__(self, parent, on_module_select):
        super().__init__(parent, corner_radius=15)
        self.on_module_select = on_module_select
        self.setup_ui()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Header section with welcome message
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(20, 10))
        
        title = ctk.CTkLabel(header_frame, text="🛡️ Local Security Toolkit", 
                           font=ctk.CTkFont(size=36, weight="bold"))
        title.pack(pady=(0, 10))
        
        subtitle = ctk.CTkLabel(header_frame, text="Welcome! Select a security tool to get started", 
                              font=ctk.CTkFont(size=16), text_color=("gray60", "gray40"))
        subtitle.pack()
        
        # Course info
        course_info = ctk.CTkLabel(header_frame, 
                                  text="MO-IT142 - Security Script Programming | Milestone 2",
                                  font=ctk.CTkFont(size=12), text_color=("gray50", "gray50"))
        course_info.pack(pady=(5, 0))
        
        # Module selection cards
        cards_container = ctk.CTkFrame(main_container, fg_color="transparent")
        cards_container.pack(fill="both", expand=True, pady=30)
        
        # Configure grid
        cards_container.grid_columnconfigure(0, weight=1)
        cards_container.grid_columnconfigure(1, weight=1)
        cards_container.grid_rowconfigure(0, weight=1)
        cards_container.grid_rowconfigure(1, weight=1)
        
        # Module data: (name, icon, description, color)
        modules = [
            ("System Info", "💻", "Monitor system resources, memory usage, and uptime", "#3B8ED0"),
            ("Network Traffic", "🌐", "Capture and analyze network packets in real-time", "#2D8C5C"),
            ("Port Scanner", "🔍", "Scan ports and identify running services", "#D97D0D"),
            ("About", "ℹ️", "Learn more about the toolkit and usage guidelines", "#7D5BA6")
        ]
        
        for idx, (name, icon, description, color) in enumerate(modules):
            row = idx // 2
            col = idx % 2
            
            # Create module card
            module_card = ctk.CTkFrame(cards_container, corner_radius=15, 
                                      fg_color=("gray80", "gray20"))
            module_card.grid(row=row, column=col, sticky="nsew", 
                           padx=15, pady=15)
            
            # Icon
            icon_label = ctk.CTkLabel(module_card, text=icon, 
                                    font=ctk.CTkFont(size=48))
            icon_label.pack(pady=(25, 10))
            
            # Module name
            name_label = ctk.CTkLabel(module_card, text=name, 
                                    font=ctk.CTkFont(size=20, weight="bold"))
            name_label.pack(pady=(0, 5))
            
            # Description
            desc_label = ctk.CTkLabel(module_card, text=description, 
                                    font=ctk.CTkFont(size=13),
                                    text_color=("gray60", "gray40"),
                                    wraplength=250)
            desc_label.pack(pady=(0, 15), padx=20)
            
            # Launch button
            launch_btn = ctk.CTkButton(module_card, text=f"Open {name}", 
                                      command=lambda n=name: self.on_module_select(n),
                                      fg_color=color, hover_color=self._darken_color(color),
                                      height=40, width=180,
                                      font=ctk.CTkFont(size=14, weight="bold"))
            launch_btn.pack(pady=(0, 25))
        
        # Footer with warning
        footer_frame = ctk.CTkFrame(main_container, corner_radius=10, 
                                   fg_color=("orange", "darkorange"))
        footer_frame.pack(fill="x", pady=(10, 0))
        
        warning_label = ctk.CTkLabel(footer_frame, 
                                    text="⚠️ Educational Use Only • Always obtain proper authorization before security testing",
                                    font=ctk.CTkFont(size=12, weight="bold"),
                                    text_color="white")
        warning_label.pack(pady=12)
    
    def _darken_color(self, hex_color):
        """Darken a hex color for hover effect"""
        # Simple darkening by reducing RGB values
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = max(0, int(r * 0.7))
        g = max(0, int(g * 0.7))
        b = max(0, int(b * 0.7))
        return f'#{r:02x}{g:02x}{b:02x}'


class MemoryProgressCard(ctk.CTkFrame):
    """Memory card with progress bar showing usage"""
    
    def __init__(self, parent, title, description=None):
        super().__init__(parent, corner_radius=10)
        self.configure(fg_color=("gray85", "gray25"))
        
        # Title 
        self.title_label = ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=14, weight="bold"))
        self.title_label.pack(pady=(15, 5))
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self, width=200, height=20)
        self.progress_bar.pack(pady=(10, 10), padx=20)
        
        # Memory usage text 
        self.usage_label = ctk.CTkLabel(self, text="0.0 GB used / 0.0 GB total", 
                                       font=ctk.CTkFont(size=24, weight="bold"))
        self.usage_label.pack(pady=5)
        
        # Description
        if description:
            self.desc_label = ctk.CTkLabel(self, text=description, font=ctk.CTkFont(size=18), 
                                         text_color=("gray55", "gray45"))
            self.desc_label.pack(pady=(0, 15))
        else:
            ctk.CTkLabel(self, text="").pack(pady=(0, 10))
    
    def update_memory(self, total_gb, available_gb):
        """Update the memory progress bar and text"""
        try:
            used_gb = total_gb - available_gb if total_gb > 0 else 0
            usage_percentage = (used_gb / total_gb) if total_gb > 0 else 0
            
            self.progress_bar.set(max(0, min(1, usage_percentage)))
                        
            self.usage_label.configure(text=f"{used_gb:.1f} / {total_gb:.1f} GB")
            
            # Color the progress bar based on usage
            if usage_percentage < 0.6:  # < 60% usage - green
                self.progress_bar.configure(progress_color="#4CAF50")
            elif usage_percentage < 0.8:  # 60-80% usage - orange
                self.progress_bar.configure(progress_color="#FF9800")
            else:  # > 80% usage - red
                self.progress_bar.configure(progress_color="#F44336")
                
        except Exception as e:
            # Fallback on error
            self.progress_bar.set(0)
            self.usage_label.configure(text="Memory info unavailable")


class InfoCard(ctk.CTkFrame):
    """Card-style info display with proper visual hierarchy"""
    
    def __init__(self, parent, title, value, description=None, value_color=None):
        super().__init__(parent, corner_radius=10)
        self.configure(fg_color=("gray85", "gray25"))
        
        # Title
        title_label = ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=14, weight="bold"))
        title_label.pack(pady=(15, 5))
        
        # Main value 
        value_label = ctk.CTkLabel(self, text=str(value), font=ctk.CTkFont(size=24, weight="bold"))
        if value_color:
            value_label.configure(text_color=value_color)
        value_label.pack(pady=5)
        
        # Description/subtitle
        if description:
            desc_label = ctk.CTkLabel(self, text=description, font=ctk.CTkFont(size=18), 
                                    text_color=("gray55", "gray45"))
            desc_label.pack(pady=(0, 15))
        else:
            ctk.CTkLabel(self, text="").pack(pady=(0, 10))


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


class SystemInfoFrame(ctk.CTkFrame):
    """System Information Frame"""
    
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.backend = SystemInfoBackend()
        self.setup_ui()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
                
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 25))
        
        title = ctk.CTkLabel(header_frame, text="System Information", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(side="left")
        
        subtitle = ctk.CTkLabel(header_frame, text="View details about your computer", 
                              font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        subtitle.pack(side="left", padx=(15, 0), anchor="s")
        
        refresh_btn = ctk.CTkButton(header_frame, text="Refresh", command=self.refresh_info,
                                  height=35, width=120)
        refresh_btn.pack(side="right")
                
        self.cards_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        self.cards_frame.pack(fill="both", expand=True)
                
        for i in range(3):
            self.cards_frame.grid_columnconfigure(i, weight=1, uniform="col")
        for i in range(2):
            self.cards_frame.grid_rowconfigure(i, weight=1, uniform="row")
                
        self.refresh_info()
    
    def refresh_info(self):
        """Refresh system information with card display"""
        
        for widget in self.cards_frame.winfo_children():
            widget.destroy()
        
        try:
            info = self.backend.get_system_info()
            
            if 'error' in info:
                error_frame = ctk.CTkFrame(self.cards_frame, fg_color=("red", "darkred"))
                error_frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
                
                error_label = ctk.CTkLabel(error_frame, text="psutil package required for full functionality",
                                         font=ctk.CTkFont(size=16, weight="bold"), text_color="white")
                error_label.pack(pady=20)
                
                install_label = ctk.CTkLabel(error_frame, text="Install with: pip install psutil",
                                           font=ctk.CTkFont(size=12), text_color="white")
                install_label.pack(pady=(0, 20))
                return
            
            # Parse memory values for progress bar
            total_memory_str = info.get('total_memory', '0 GB')
            available_memory_str = info.get('available_memory', '0 GB')
            
            # Extract numeric values
            try:
                total_gb = float(total_memory_str.split()[0]) if 'GB' in total_memory_str else 0
                available_gb = float(available_memory_str.split()[0]) if 'GB' in available_memory_str else 0
            except (ValueError, IndexError):
                total_gb = 0
                available_gb = 0
            
            # Format uptime with color coding
            uptime_info = self.format_uptime(info.get('uptime_seconds', 'N/A'))
            if isinstance(uptime_info, tuple):
                uptime_text, uptime_color = uptime_info
            else:
                uptime_text, uptime_color = uptime_info, None
            
            # Add restart advice for long uptimes
            uptime_desc = "Time since boot"
            if uptime_color == "red":
                uptime_desc += " - Consider restarting"
            
            # Create regular info cards with proper hierarchy
            card_data = [
                ("Operating System", info.get('platform', 'Unknown'), 
                 f"Version: {info.get('platform_release', 'Unknown')}", None),
                ("Processor Cores", info.get('cpu_count', 'N/A'), "Logical processors", None),
                ("System Uptime", uptime_text, uptime_desc, uptime_color),
                ("Status", "Running", "System operational", "green")
            ]
                        
            card_positions = [0, 1, 3, 4]  
            for i, card_info in enumerate(card_data):
                if i < len(card_positions):
                    pos = card_positions[i]
                    row = pos // 3
                    col = pos % 3
                    title, value, desc, color = card_info
                    card = InfoCard(self.cards_frame, title, value, desc, color)
                    card.grid(row=row, column=col, sticky="nsew", padx=10, pady=10)
                        
            memory_card = MemoryProgressCard(self.cards_frame, "Memory Usage", "System RAM")
            memory_card.grid(row=0, column=2, sticky="nsew", padx=10, pady=10)
            memory_card.update_memory(total_gb, available_gb)
                
        except Exception as e:
            error_frame = ctk.CTkFrame(self.cards_frame, fg_color=("red", "darkred"))
            error_frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=10)
            
            error_label = ctk.CTkLabel(error_frame, text=f"Error: {str(e)}",
                                     font=ctk.CTkFont(size=14), text_color="white")
            error_label.pack(pady=20)
    
    def format_uptime(self, uptime_str):
        """Format uptime string for better readability and return color info"""
        if isinstance(uptime_str, str) and 'seconds' in uptime_str:
            try:
                seconds = float(uptime_str.split()[0])
                hours = seconds / 3600
                days = hours / 24
                
                if days >= 1:
                    formatted_time = f"{days:.1f} days"
                elif hours >= 1:
                    formatted_time = f"{hours:.1f} hours"
                else:
                    formatted_time = f"{seconds/60:.0f} minutes"
                
                # Determine color based on uptime
                if days < 7:
                    color = "green"
                elif days < 14:
                    color = "orange"
                else:
                    color = "red"
                
                return formatted_time, color
            except:
                return uptime_str, None
        return uptime_str, None


class NetworkTrafficFrame(ctk.CTkFrame):
    """Network Traffic Analyzer Frame"""
    
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.backend = NetworkTrafficBackend()
        self.setup_ui()
        self.setup_callbacks()
    
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
                
        warning = ctk.CTkLabel(main_container, text="Requires administrator/root privileges • Only capture on networks you own or have permission to monitor", 
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
        
        self.status_label = ctk.CTkLabel(status_inner, text="Ready to capture",
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
    
    def stop_capture(self):
        """Stop packet capture"""
        self.backend.stop_capture()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
    
    def clear_display(self):
        """Clear packet display"""
        self.packet_table.clear()
        self.backend.packet_count = 0
        self.packet_count_label.configure(text="Packets: 0")
        self.status_label.configure(text="Display cleared")
    
    # Callback methods
    def on_packet_captured(self, packet_data):
        """Called when a packet is captured"""
        def update_ui():
            count = self.backend.get_packet_count()
            tag = 'evenrow' if count % 2 == 0 else 'oddrow'
            
            self.packet_table.insert([
                packet_data['timestamp'],
                packet_data['src_ip'],
                packet_data['dst_ip'],
                packet_data['protocol'],
                packet_data['src_port'],
                packet_data['dst_port'],
                str(packet_data['size'])
            ], tags=[tag])
            
            self.packet_count_label.configure(text=f"Packets: {count}")
            
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
            self.stop_btn.configure(state="disabled")
        ])
    
    def on_capture_started(self):
        """Called when capture starts"""
        self.after(0, lambda: self.status_label.configure(text="Capturing packets..."))
    
    def on_capture_stopped(self):
        """Called when capture stops"""
        self.after(0, lambda: self.status_label.configure(text="Capture stopped"))


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
        
        
        warning = ctk.CTkLabel(main_container, text="Only scan systems you own or have permission to test", 
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


class AboutFrame(ctk.CTkFrame):
    """About/Help Frame"""
    
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.setup_ui()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
                
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 25))
        
        title = ctk.CTkLabel(header_frame, text="Local Security Toolkit", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack()
        
        version = ctk.CTkLabel(header_frame, text="Version 1.0", 
                             font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        version.pack(pady=(5, 0))
                
        content_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        content_frame.pack(fill="both", expand=True)
                
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
                
        overview_card = ctk.CTkFrame(content_frame, corner_radius=10)
        overview_card.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        
        ctk.CTkLabel(overview_card, text="Overview", 
                   font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(20, 10))
        
        overview_text = """Security and system monitoring tools for educational and authorized testing purposes.
This toolkit helps you monitor your system and test security configurations safely and responsibly."""
        
        ctk.CTkLabel(overview_card, text=overview_text, 
                   font=ctk.CTkFont(size=14), wraplength=600).pack(pady=(0, 20))
        
        # Tools cards
        tools_info = [
            ("System Information", "View computer details like memory, processor cores, and uptime."),
            ("Network Traffic Analyzer", "Capture and analyze network packets in real-time with protocol filtering."),
            ("Port Scanner", "Check which network services are open. Only scan authorized systems."),
        ]
        
        for i, (tool_name, description) in enumerate(tools_info):
            row = (i // 2) + 1
            col = i % 2
            
            tool_card = ctk.CTkFrame(content_frame, corner_radius=10)
            tool_card.grid(row=row, column=col, sticky="nsew", 
                         padx=(0 if col == 0 else 7, 7 if col == 0 else 0), pady=7)
            
            ctk.CTkLabel(tool_card, text=tool_name, 
                       font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(15, 5))
            
            ctk.CTkLabel(tool_card, text=description, 
                       font=ctk.CTkFont(size=14), wraplength=250, 
                       text_color=("gray60", "gray40")).pack(pady=(0, 15), padx=15)
        
        # Important notes card
        notes_card = ctk.CTkFrame(content_frame, corner_radius=10)
        notes_card.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(15, 0))
        
        ctk.CTkLabel(notes_card, text="Important Notes", 
                   font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(20, 10))
        
        notes_text = """- Only scan systems and networks you own or have permission to test
- Unauthorized scanning/packet capture may violate local laws and policies
- Network traffic capture requires administrator privileges
- Install dependencies: pip install psutil scapy
- This tool is for educational and authorized security testing only"""
        
        ctk.CTkLabel(notes_card, text=notes_text, 
                   font=ctk.CTkFont(size=14), justify="left").pack(pady=(0, 20), padx=20)


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
                
        # Show Welcome screen by default
        self.show_frame("Welcome")
    
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
        self.sidebar.grid_rowconfigure(9, weight=1)
                
        sidebar_title = ctk.CTkLabel(self.sidebar, text="Security Toolkit", 
                                   font=ctk.CTkFont(size=20, weight="bold"))
        sidebar_title.grid(row=0, column=0, padx=20, pady=(30, 20))
                
        self.sidebar_buttons = {}
        tools = [
            "Welcome",
            "System Info",
            "Network Traffic",
            "Port Scanner",
            "About"
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
        self.frames["Welcome"] = WelcomeFrame(self.content_frame, on_module_select=self.show_frame)
        self.frames["System Info"] = SystemInfoFrame(self.content_frame)
        self.frames["Network Traffic"] = NetworkTrafficFrame(self.content_frame)
        self.frames["Port Scanner"] = PortScannerFrame(self.content_frame)
        self.frames["About"] = AboutFrame(self.content_frame)
                
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
