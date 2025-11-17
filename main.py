# main.py
"""
Local Security Toolkit
A GUI application for network monitoring and security testing.

Requirements:
- customtkinter: pip install customtkinter
- scapy: pip install scapy

Usage:
python main.py
"""

import sys
import tkinter.messagebox as msgbox

try:
    import customtkinter as ctk
except ImportError:
    print("Error: customtkinter is required")
    print("Install with: pip install customtkinter")
    sys.exit(1)

try:
    from frontend import MainApplication
except ImportError as e:
    print(f"Error importing frontend: {e}")
    sys.exit(1)


def check_dependencies():
    """Check and warn about optional dependencies"""
    missing_deps = []
    
    try:
        import scapy
    except ImportError:
        missing_deps.append("scapy")
    
    if missing_deps:
        # Show warning but don't exit - these are optional
        dep_list = "\n".join([f"- {dep}" for dep in missing_deps])
        
        msgbox.showwarning(
            "Required Dependency Missing",
            f"The following package is not installed:\n{dep_list}\n\n"
            f"Network Traffic Analyzer requires scapy.\n\n"
            f"To install: pip install {' '.join(missing_deps)}"
        )


def main():
    """Main entry point"""
    try:
        # Check dependencies
        check_dependencies()
        
        # Create and configure the application
        app = MainApplication()
        
        # Handle window close
        def on_closing():
            # Stop any running operations before closing
            try:
                # Stop port scanner if running
                port_scanner_frame = app.frames.get("Port Scanner")
                if port_scanner_frame and port_scanner_frame.backend.is_scanning():
                    if msgbox.askyesno("Scan in Progress", "A port scan is currently running. Stop the scan and exit?"):
                        port_scanner_frame.backend.stop_scan()
                    else:
                        return  # Don't close if user cancels
                
                # Stop network traffic capture if running
                network_traffic_frame = app.frames.get("Network Traffic")
                if network_traffic_frame and network_traffic_frame.backend.is_capturing:
                    if msgbox.askyesno("Capture in Progress", "Network capture is currently running. Stop capture and exit?"):
                        network_traffic_frame.backend.stop_capture()
                    else:
                        return  # Don't close if user cancels
            except Exception:
                pass  # Ignore errors during cleanup
            
            app.destroy()
        
        app.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Start the GUI
        print("Starting Local Security Toolkit...")
        print("Note: Network capture requires administrator/root privileges")
        app.mainloop()
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        error_msg = f"Failed to start application:\n\n{str(e)}\n\nPlease check that all dependencies are installed."
        print(f"Error: {error_msg}")
        
        # Try to show GUI error if possible
        try:
            msgbox.showerror("Application Error", error_msg)
        except:
            pass  # GUI might not be available
        
        sys.exit(1)


if __name__ == "__main__":
    main()