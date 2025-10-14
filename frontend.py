import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
import threading
import tkinter.messagebox as msgbox
import tkinter.filedialog as filedialog
from pathlib import Path
from typing import Optional

from backend import (
    SystemInfoBackend, ProcessBackend, NetworkBackend, 
    FileIntegrityBackend, PortScannerBackend, NetworkTrafficBackend
)


class MemoryProgressCard(ctk.CTkFrame):
    """Memory card with progress bar showing usage"""
    
    def __init__(self, parent, title, description=None):
        super().__init__(parent, corner_radius=10)
        self.configure(fg_color=("gray85", "gray25"))
        
        # Title - consistent with InfoCard
        self.title_label = ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=14, weight="bold"))
        self.title_label.pack(pady=(15, 5))
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self, width=200, height=20)
        self.progress_bar.pack(pady=(10, 10), padx=20)
        
        # Memory usage text - consistent with InfoCard values
        self.usage_label = ctk.CTkLabel(self, text="0.0 GB used / 0.0 GB total", 
                                       font=ctk.CTkFont(size=24, weight="bold"))
        self.usage_label.pack(pady=5)
        
        # Description - consistent with InfoCard
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
            
            # Update progress bar (clamp between 0 and 1)
            self.progress_bar.set(max(0, min(1, usage_percentage)))
            
            # Update text - show simplified format
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
        
        # Main value - larger and prominent
        value_label = ctk.CTkLabel(self, text=str(value), font=ctk.CTkFont(size=24, weight="bold"))
        if value_color:
            value_label.configure(text_color=value_color)
        value_label.pack(pady=5)
        
        # Description/subtitle - smaller and muted
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
        
        # Configure treeview style for dark theme
        style = ttk.Style()
        style.theme_use("clam")
        
        # Configure colors for dark theme
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
        
        # Header section
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
        
        # Cards container
        self.cards_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        self.cards_frame.pack(fill="both", expand=True)
        
        # Configure grid for cards
        for i in range(3):
            self.cards_frame.grid_columnconfigure(i, weight=1, uniform="col")
        for i in range(2):
            self.cards_frame.grid_rowconfigure(i, weight=1, uniform="row")
        
        # Load initial data
        self.refresh_info()
    
    def refresh_info(self):
        """Refresh system information with card display"""
        # Clear existing cards
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
            
            # Extract numeric values (assuming format like "15.7 GB")
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
            
            # Position regular cards
            card_positions = [0, 1, 3, 4]  # Skip position 2 for memory progress card
            for i, card_info in enumerate(card_data):
                if i < len(card_positions):
                    pos = card_positions[i]
                    row = pos // 3
                    col = pos % 3
                    title, value, desc, color = card_info
                    card = InfoCard(self.cards_frame, title, value, desc, color)
                    card.grid(row=row, column=col, sticky="nsew", padx=10, pady=10)
            
            # Create memory progress card at position 2 (row 0, col 2)
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


class ProcessMonitorFrame(ctk.CTkFrame):
    """Process Monitor Frame"""
    
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.backend = ProcessBackend()
        self.processes = []
        self.filtered_processes = []
        self.setup_ui()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Header section
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))
        
        title = ctk.CTkLabel(header_frame, text="Process Monitor", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(side="left")
        
        subtitle = ctk.CTkLabel(header_frame, text="View and manage running programs", 
                              font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        subtitle.pack(side="left", padx=(15, 0), anchor="s")
        
        # Controls section
        controls_frame = ctk.CTkFrame(main_container, corner_radius=10)
        controls_frame.pack(fill="x", pady=(0, 15))
        
        # Top row - refresh and search
        top_controls = ctk.CTkFrame(controls_frame, fg_color="transparent")
        top_controls.pack(fill="x", padx=20, pady=(15, 10))
        
        refresh_btn = ctk.CTkButton(top_controls, text="Refresh List", command=self.refresh_processes,
                                  height=35, width=140)
        refresh_btn.pack(side="left")
        
        # Search controls
        ctk.CTkLabel(top_controls, text="Search:", 
                   font=ctk.CTkFont(size=12)).pack(side="left", padx=(20, 5))
        
        self.search_entry = ctk.CTkEntry(top_controls, width=200, placeholder_text="Enter process name...")
        self.search_entry.pack(side="left", padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", self.on_search_changed)
        
        clear_search_btn = ctk.CTkButton(top_controls, text="Clear", command=self.clear_search,
                                       height=35, width=80)
        clear_search_btn.pack(side="left")
        
        # Middle row - process termination
        middle_controls = ctk.CTkFrame(controls_frame, fg_color="transparent")
        middle_controls.pack(fill="x", padx=20, pady=(0, 10))
        
        ctk.CTkLabel(middle_controls, text="End Process:", 
                   font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")
        
        ctk.CTkLabel(middle_controls, text="PID:", 
                   font=ctk.CTkFont(size=12)).pack(side="left", padx=(15, 5))
        
        self.pid_entry = ctk.CTkEntry(middle_controls, width=80, placeholder_text="12345")
        self.pid_entry.pack(side="left", padx=(0, 15))
        
        kill_btn = ctk.CTkButton(middle_controls, text="End Process", command=self.kill_process,
                               fg_color="red", hover_color="darkred", height=35, width=130)
        kill_btn.pack(side="left")
        
        # Warning label
        warning_label = ctk.CTkLabel(controls_frame, text="Ends the selected program. Use with caution.",
                                   font=ctk.CTkFont(size=11), text_color=("orange", "orange"))
        warning_label.pack(pady=(0, 15))
        
        # Process table
        self.create_process_table(main_container)
        
        # Load initial data
        self.refresh_processes()
    
    def create_process_table(self, parent):
        """Create the process table"""
        table_frame = ctk.CTkFrame(parent, corner_radius=10)
        table_frame.pack(fill="both", expand=True)
        
        # Header
        header_label = ctk.CTkLabel(table_frame, text="Running Processes", 
                                  font=ctk.CTkFont(size=16, weight="bold"))
        header_label.pack(pady=(15, 10))
        
        # Table columns
        columns = {
            'pid': ('PID', 80),
            'name': ('Program Name', 200),
            'username': ('User', 120),
            'cpu': ('CPU %', 80),
            'memory': ('Memory', 100)
        }
        
        self.process_table = TableFrame(table_frame, columns)
        self.process_table.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Configure alternating row colors
        self.process_table.configure_tags({
            'evenrow': {'background': '#363636'},
            'oddrow': {'background': '#2b2b2b'}
        })
    
    def refresh_processes(self):
        """Refresh process list"""
        self.process_table.clear()
        
        def load_processes():
            try:
                self.processes = self.backend.list_processes()
                self.filtered_processes = self.processes.copy()
                self.display_processes()
            except Exception as e:
                self.after(0, lambda: msgbox.showerror("Error", f"Failed to load processes: {str(e)}"))
        
        thread = threading.Thread(target=load_processes, daemon=True)
        thread.start()
    
    def on_search_changed(self, event=None):
        """Handle search input changes"""
        search_term = self.search_entry.get().lower().strip()
        
        if not search_term:
            self.filtered_processes = self.processes.copy()
        else:
            self.filtered_processes = []
            for proc in self.processes:
                if (search_term in proc.get('name', '').lower() or 
                    search_term in proc.get('username', '').lower() or
                    search_term in str(proc.get('pid', ''))):
                    self.filtered_processes.append(proc)
        
        self.display_processes()
    
    def clear_search(self):
        """Clear search field and show all processes"""
        self.search_entry.delete(0, 'end')
        self.filtered_processes = self.processes.copy()
        self.display_processes()
    
    def display_processes(self):
        """Display process list in table"""
        def update_ui():
            self.process_table.clear()
            
            processes_to_show = self.filtered_processes
            
            if processes_to_show and isinstance(processes_to_show[0], dict) and 'error' in processes_to_show[0]:
                # Show error in table
                self.process_table.insert(['ERROR', processes_to_show[0]['error'], '', '', ''])
                return
            
            # Show search results count
            search_term = self.search_entry.get().strip()
            if search_term:
                result_count = len(processes_to_show)
                if result_count == 0:
                    self.process_table.insert(['', f"No processes found matching '{search_term}'", '', '', ''])
                    return
            
            # Add processes to table (limit to 100 for performance)
            for i, proc in enumerate(processes_to_show[:100]):
                try:
                    memory_mb = proc['memory_rss'] / (1024 * 1024) if proc['memory_rss'] else 0
                    memory_str = f"{memory_mb:.1f} MB" if memory_mb > 0 else "0 MB"
                    cpu_str = f"{proc['cpu_percent']:.1f}%" if proc['cpu_percent'] else "0.0%"
                    
                    row_tag = 'evenrow' if i % 2 == 0 else 'oddrow'
                    
                    self.process_table.insert([
                        str(proc['pid']),
                        proc['name'][:30] if proc['name'] else 'Unknown',
                        proc['username'][:15] if proc['username'] else 'Unknown',
                        cpu_str,
                        memory_str
                    ], tags=[row_tag])
                    
                except (KeyError, TypeError):
                    continue
        
        self.after(0, update_ui)
    
    def kill_process(self):
        """Kill selected process"""
        try:
            pid = int(self.pid_entry.get())
        except ValueError:
            msgbox.showerror("Error", "Please enter a valid PID number")
            return
        
        # Confirm action
        if not msgbox.askyesno("Confirm Action", 
                              f"End process with PID {pid}?\n\nThis may cause data loss if the program has unsaved work."):
            return
        
        def kill_proc():
            try:
                success = self.backend.kill_process(pid)
                message = f"Process {pid} ended successfully" if success else f"Failed to end process {pid}"
                self.after(0, lambda: msgbox.showinfo("Result", message))
                if success:
                    self.after(0, self.refresh_processes)
            except Exception as e:
                self.after(0, lambda: msgbox.showerror("Error", f"Error ending process: {str(e)}"))
        
        thread = threading.Thread(target=kill_proc, daemon=True)
        thread.start()


class NetworkConnectionsFrame(ctk.CTkFrame):
    """Network Connections Frame"""
    
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.backend = NetworkBackend()
        self.setup_ui()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Header section
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))
        
        title = ctk.CTkLabel(header_frame, text="Network Connections", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(side="left")
        
        subtitle = ctk.CTkLabel(header_frame, text="Monitor active network connections", 
                              font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        subtitle.pack(side="left", padx=(15, 0), anchor="s")
        
        # Controls
        controls_frame = ctk.CTkFrame(main_container, corner_radius=10)
        controls_frame.pack(fill="x", pady=(0, 15))
        
        refresh_btn = ctk.CTkButton(controls_frame, text="Refresh", command=self.refresh_connections,
                                  height=35, width=120)
        refresh_btn.pack(padx=20, pady=15)
        
        # Connections table
        self.create_connections_table(main_container)
        
        # Load initial data
        self.refresh_connections()
    
    def create_connections_table(self, parent):
        """Create the connections table"""
        table_frame = ctk.CTkFrame(parent, corner_radius=10)
        table_frame.pack(fill="both", expand=True)
        
        # Header
        header_label = ctk.CTkLabel(table_frame, text="Active Connections", 
                                  font=ctk.CTkFont(size=16, weight="bold"))
        header_label.pack(pady=(15, 10))
        
        # Table columns
        columns = {
            'local': ('Local Address', 180),
            'remote': ('Remote Address', 180),
            'status': ('Status', 120),
            'pid': ('Program (PID)', 120)
        }
        
        self.connections_table = TableFrame(table_frame, columns)
        self.connections_table.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Configure alternating row colors
        self.connections_table.configure_tags({
            'evenrow': {'background': '#363636'},
            'oddrow': {'background': '#2b2b2b'},
            'listening': {'background': '#1a5d1a', 'foreground': 'lightgreen'},
            'established': {'background': '#1a4d5d', 'foreground': 'lightblue'}
        })
    
    def refresh_connections(self):
        """Refresh network connections"""
        self.connections_table.clear()
        
        def load_connections():
            try:
                connections = self.backend.list_connections()
                self.display_connections(connections)
            except Exception as e:
                self.after(0, lambda: msgbox.showerror("Error", f"Failed to load connections: {str(e)}"))
        
        thread = threading.Thread(target=load_connections, daemon=True)
        thread.start()
    
    def display_connections(self, connections):
        """Display connections in table"""
        def update_ui():
            self.connections_table.clear()
            
            if connections and isinstance(connections[0], dict) and 'error' in connections[0]:
                # Show error in table
                self.connections_table.insert(['ERROR', connections[0]['error'], '', ''])
                return
            
            # Add connections to table
            for i, conn in enumerate(connections):
                try:
                    pid_text = str(conn['pid']) if conn['pid'] != 'N/A' else 'N/A'
                    status = conn['status']
                    
                    # Determine row styling
                    row_tags = []
                    if status == 'LISTEN':
                        row_tags.append('listening')
                    elif status == 'ESTABLISHED':
                        row_tags.append('established')
                    else:
                        row_tags.append('evenrow' if i % 2 == 0 else 'oddrow')
                    
                    self.connections_table.insert([
                        conn['local_addr'][:25],
                        conn['remote_addr'][:25],
                        status,
                        pid_text
                    ], tags=row_tags)
                    
                except (KeyError, TypeError):
                    continue
        
        self.after(0, update_ui)


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
        
        # Header section
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))
        
        title = ctk.CTkLabel(header_frame, text="Network Traffic Analyzer", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(side="left")
        
        subtitle = ctk.CTkLabel(header_frame, text="Capture and analyze network packets in real-time", 
                              font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        subtitle.pack(side="left", padx=(15, 0), anchor="s")
        
        # Warning
        warning = ctk.CTkLabel(main_container, text="Requires administrator/root privileges • Only capture on networks you own or have permission to monitor", 
                              text_color="orange", font=ctk.CTkFont(size=12, weight="bold"))
        warning.pack(pady=(0, 15))
        
        # Controls section
        self.create_controls(main_container)
        
        # Status section
        self.create_status_section(main_container)
        
        # Packet table
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
        
        # Header
        header_label = ctk.CTkLabel(table_frame, text="Captured Packets", 
                                  font=ctk.CTkFont(size=16, weight="bold"))
        header_label.pack(pady=(15, 10))
        
        # Table columns
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
        
        # Configure alternating row colors
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


class FileIntegrityFrame(ctk.CTkFrame):
    """File Integrity Frame"""
    
    def __init__(self, parent):
        super().__init__(parent, corner_radius=15)
        self.backend = FileIntegrityBackend()
        self.current_file = None
        self.setup_ui()
    
    def setup_ui(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Header section
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))
        
        title = ctk.CTkLabel(header_frame, text="File Integrity Checker", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(side="left")
        
        subtitle = ctk.CTkLabel(header_frame, text="Monitor files for unauthorized changes using secure hashes", 
                              font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        subtitle.pack(side="left", padx=(15, 0), anchor="s")
        
        # File selection section
        self.create_file_selection_section(main_container)
        
        # Baseline settings section
        self.create_baseline_section(main_container)
        
        # Results section
        self.create_results_section(main_container)
    
    def create_file_selection_section(self, parent):
        """Create file selection section"""
        file_section = ctk.CTkFrame(parent, corner_radius=10)
        file_section.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(file_section, text="Select a File", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        file_controls = ctk.CTkFrame(file_section, fg_color="transparent")
        file_controls.pack(pady=(0, 15))
        
        select_btn = ctk.CTkButton(file_controls, text="Choose File", command=self.select_file,
                                 height=35, width=120)
        select_btn.pack(side="left", padx=(20, 10))
        
        self.file_label = ctk.CTkLabel(file_controls, text="No file selected",
                                     font=ctk.CTkFont(size=12), text_color=("gray60", "gray40"))
        self.file_label.pack(side="left")
    
    def create_baseline_section(self, parent):
        """Create baseline settings section"""
        baseline_section = ctk.CTkFrame(parent, corner_radius=10)
        baseline_section.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(baseline_section, text="Baseline Settings", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        # Input row
        input_row = ctk.CTkFrame(baseline_section, fg_color="transparent")
        input_row.pack(pady=(0, 10))
        
        ctk.CTkLabel(input_row, text="Baseline Name:", 
                   font=ctk.CTkFont(size=12)).pack(side="left", padx=(20, 5))
        
        self.baseline_entry = ctk.CTkEntry(input_row, width=150, placeholder_text="my_file_baseline")
        self.baseline_entry.pack(side="left", padx=(0, 20))
        
        # Button row
        button_row = ctk.CTkFrame(baseline_section, fg_color="transparent")
        button_row.pack(pady=(0, 15))
        
        compute_btn = ctk.CTkButton(button_row, text="Compute Hash", command=self.compute_hash,
                                  height=35, width=120)
        compute_btn.pack(side="left", padx=(20, 10))
        
        save_btn = ctk.CTkButton(button_row, text="Save Baseline", command=self.save_baseline,
                               fg_color="green", hover_color="darkgreen", height=35, width=120)
        save_btn.pack(side="left", padx=(0, 10))
        
        verify_btn = ctk.CTkButton(button_row, text="Verify File", command=self.verify_baseline,
                                 fg_color="orange", hover_color="darkorange", height=35, width=120)
        verify_btn.pack(side="left")
        
        # Help text
        help_label = ctk.CTkLabel(baseline_section, 
                                text="Compute shows the file's fingerprint - Save stores current state - Verify checks for changes",
                                font=ctk.CTkFont(size=11), text_color=("gray60", "gray40"))
        help_label.pack(pady=(0, 15))
    
    def create_results_section(self, parent):
        """Create results section"""
        results_section = ctk.CTkFrame(parent, corner_radius=10)
        results_section.pack(fill="both", expand=True)
        
        ctk.CTkLabel(results_section, text="Results", 
                   font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        # Results table
        columns = {
            'timestamp': ('Timestamp', 150),
            'action': ('Action', 100),
            'file': ('File', 200),
            'status': ('Status', 100),
            'hash': ('Hash (first 16 chars)', 200)
        }
        
        self.results_table = TableFrame(results_section, columns)
        self.results_table.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Configure result colors
        self.results_table.configure_tags({
            'success': {'background': '#1a5d1a', 'foreground': 'lightgreen'},
            'failure': {'background': '#5d1a1a', 'foreground': 'lightcoral'},
            'info': {'background': '#1a4d5d', 'foreground': 'lightblue'}
        })
    
    def select_file(self):
        """Select file for integrity checking"""
        filename = filedialog.askopenfilename(
            title="Select File for Integrity Check",
            filetypes=[("All Files", "*.*")]
        )
        if filename:
            self.current_file = filename
            file_name = Path(filename).name
            self.file_label.configure(text=f"Selected: {file_name}")
    
    def add_result(self, action, status, hash_value=None):
        """Add result to the table"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        file_name = Path(self.current_file).name if self.current_file else "N/A"
        hash_display = hash_value[:16] + "..." if hash_value else "N/A"
        
        if status in ["PASSED", "Computed", "Saved"]:
            tag = 'success'
        elif status in ["FAILED", "Error"]:
            tag = 'failure'
        else:
            tag = 'info'
        
        self.results_table.insert([timestamp, action, file_name, status, hash_display], tags=[tag])
    
    def compute_hash(self):
        """Compute hash of selected file"""
        if not self.current_file:
            msgbox.showerror("Error", "Please select a file first")
            return
        
        def compute():
            try:
                hash_value = self.backend.compute_hash(self.current_file)
                self.after(0, lambda: self.add_result("Compute", "Computed", hash_value))
            except Exception as e:
                self.after(0, lambda: [
                    self.add_result("Compute", "Error"),
                    msgbox.showerror("Error", f"Failed to compute hash: {str(e)}")
                ])
        
        thread = threading.Thread(target=compute, daemon=True)
        thread.start()
    
    def save_baseline(self):
        """Save baseline hash"""
        if not self.current_file:
            msgbox.showerror("Error", "Please select a file first")
            return
        
        baseline_name = self.baseline_entry.get().strip()
        if not baseline_name:
            msgbox.showerror("Error", "Please enter a baseline name")
            return
        
        def save():
            try:
                hash_value = self.backend.compute_hash(self.current_file)
                self.backend.save_baseline(baseline_name, self.current_file, hash_value)
                self.after(0, lambda: self.add_result("Save", "Saved", hash_value))
            except Exception as e:
                self.after(0, lambda: [
                    self.add_result("Save", "Error"),
                    msgbox.showerror("Error", f"Failed to save baseline: {str(e)}")
                ])
        
        thread = threading.Thread(target=save, daemon=True)
        thread.start()
    
    def verify_baseline(self):
        """Verify file against baseline"""
        if not self.current_file:
            msgbox.showerror("Error", "Please select a file first")
            return
        
        baseline_name = self.baseline_entry.get().strip()
        if not baseline_name:
            msgbox.showerror("Error", "Please enter a baseline name")
            return
        
        def verify():
            try:
                is_valid, current_hash = self.backend.verify(baseline_name, self.current_file)
                status = "PASSED" if is_valid else "FAILED"
                self.after(0, lambda: self.add_result("Verify", status, current_hash))
                
                if not is_valid:
                    self.after(0, lambda: msgbox.showwarning("File Changed", 
                                                           "File has been modified since baseline was saved!"))
            except Exception as e:
                self.after(0, lambda: [
                    self.add_result("Verify", "Error"),
                    msgbox.showerror("Error", f"Verification failed: {str(e)}")
                ])
        
        thread = threading.Thread(target=verify, daemon=True)
        thread.start()


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
        
        # Warning
        warning = ctk.CTkLabel(main_container, text="Only scan systems you own or have permission to test", 
                              text_color="orange", font=ctk.CTkFont(size=12, weight="bold"))
        warning.pack(pady=(0, 15))
        
        # Input and controls section
        self.create_scan_controls(main_container)
        
        # Progress section
        self.create_progress_section(main_container)
        
        # Results section
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
        
        # Configure result colors
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
        
        # Header section
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 25))
        
        title = ctk.CTkLabel(header_frame, text="Local Security Toolkit", 
                           font=ctk.CTkFont(size=28, weight="bold"))
        title.pack()
        
        version = ctk.CTkLabel(header_frame, text="Version 1.0", 
                             font=ctk.CTkFont(size=14), text_color=("gray60", "gray40"))
        version.pack(pady=(5, 0))
        
        # Content area with cards
        content_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        content_frame.pack(fill="both", expand=True)
        
        # Configure grid
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
        
        # Overview card
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
            ("Process Monitor", "View and manage running programs. End unresponsive applications."),
            ("Network Connections", "Monitor active network connections and see what's communicating."),
            ("Network Traffic", "Capture and analyze network packets in real-time with protocol filtering."),
            ("Port Scanner", "Check which network services are open. Only scan authorized systems."),
            ("File Integrity Checker", "Monitor important files for changes using secure hash fingerprints."),
        ]
        
        for i, (tool_name, description) in enumerate(tools_info):
            row = (i // 2) + 1
            col = i % 2
            
            tool_card = ctk.CTkFrame(content_frame, corner_radius=10)
            tool_card.grid(row=row, column=col, sticky="nsew", padx=(0 if col == 0 else 7, 7 if col == 0 else 0), pady=7)
            
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
- Some features require administrator privileges (especially packet capture)
- Install dependencies: pip install psutil scapy
- Always confirm destructive actions like ending processes
- This tool is for educational and authorized security testing only"""
        
        ctk.CTkLabel(notes_card, text=notes_text, 
                   font=ctk.CTkFont(size=14), justify="left").pack(pady=(0, 20), padx=20)


class MainApplication(ctk.CTk):
    """Main Application Window"""
    
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("Local Security Toolkit")
        self.geometry("1200x820")
        
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create UI
        self.setup_ui()
        
        # Center window after UI is created
        self.center_window()
        
        # Show initial frame
        self.show_frame("System Info")
    
    def center_window(self):
        """Center the window on screen"""
        self.update_idletasks()
        width = 1200
        height = 820
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_ui(self):
        """Setup the main UI"""
        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Create sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(9, weight=1)
        
        # Sidebar title
        sidebar_title = ctk.CTkLabel(self.sidebar, text="Security Toolkit", 
                                   font=ctk.CTkFont(size=20, weight="bold"))
        sidebar_title.grid(row=0, column=0, padx=20, pady=(30, 20))
        
        # Sidebar buttons
        self.sidebar_buttons = {}
        tools = [
            "System Info",
            "Process Monitor", 
            "Network Connections",
            "Network Traffic",
            "Port Scanner",
            "File Integrity",
            "About"
        ]
        
        for i, tool in enumerate(tools, 1):
            btn = ctk.CTkButton(self.sidebar, text=tool, 
                               command=lambda t=tool: self.show_frame(t),
                               width=200, height=45, font=ctk.CTkFont(size=14),
                               anchor="center")
            btn.grid(row=i, column=0, padx=10, pady=8)
            self.sidebar_buttons[tool] = btn
        
        # Create main content area
        self.content_frame = ctk.CTkFrame(self, corner_radius=0)
        self.content_frame.grid(row=0, column=1, sticky="nsew")
        
        # Create all frames
        self.frames = {}
        self.frames["System Info"] = SystemInfoFrame(self.content_frame)
        self.frames["Process Monitor"] = ProcessMonitorFrame(self.content_frame)
        self.frames["Network Connections"] = NetworkConnectionsFrame(self.content_frame)
        self.frames["Network Traffic"] = NetworkTrafficFrame(self.content_frame)
        self.frames["Port Scanner"] = PortScannerFrame(self.content_frame)
        self.frames["File Integrity"] = FileIntegrityFrame(self.content_frame)
        self.frames["About"] = AboutFrame(self.content_frame)
        
        # Configure content frame grid
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
    
    def show_frame(self, frame_name):
        """Show the selected frame"""
        # Hide all frames
        for frame in self.frames.values():
            frame.grid_remove()
        
        # Show selected frame
        if frame_name in self.frames:
            self.frames[frame_name].grid(row=0, column=0, sticky="nsew")
        
        # Update button states
        for name, btn in self.sidebar_buttons.items():
            if name == frame_name:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color=["#3B8ED0", "#1F6AA5"])