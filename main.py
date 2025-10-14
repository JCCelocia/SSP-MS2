"""
Local Security Toolkit
A GUI application for system monitoring and security testing.

Requirements:
- customtkinter: pip install customtkinter
- psutil (optional): pip install psutil

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
    try:
        import psutil
    except ImportError:
        # Show warning but don't exit - psutil is optional
        msgbox.showwarning(
            "Optional Dependency Missing",
            "The 'psutil' package is not installed.\n\n"
            "Some features will have limited functionality:\n"
            "- System Information\n"
            "- Process Monitor\n"
            "- Network Connections\n\n"
            "To install: pip install psutil"
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
            # Stop any running scans before closing
            try:
                port_scanner_frame = app.frames.get("Port Scanner")
                if port_scanner_frame and port_scanner_frame.backend.is_scanning():
                    if msgbox.askyesno("Scan in Progress", "A port scan is currently running. Stop the scan and exit?"):
                        port_scanner_frame.backend.stop_scan()
                    else:
                        return  # Don't close if user cancels
            except Exception:
                pass  # Ignore errors during cleanup
            
            app.destroy()
        
        app.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Start the GUI
        print("Starting Local Security Toolkit...")
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