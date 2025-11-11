"""
Production-Ready Web Security Scanner GUI
Educational/Professional Vulnerability Assessment Tool - GUI Version
Version: 2.0.0
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import time
import json
from datetime import datetime
from pathlib import Path
import sys
import os

# Import the scanner modules
from vuln_scanner import (
    VulnerabilityScanner, ScanConfig, Vulnerability, 
    VulnType, SeverityLevel, VERSION, BANNER
)


class ScannerGUI(tk.Tk):
    """Main GUI Application for Vulnerability Scanner"""
    
    def __init__(self):
        super().__init__()
        
        self.title(f"Web Security Scanner v{VERSION}")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure("Title.TLabel", font=("Arial", 16, "bold"))
        self.style.configure("Subtitle.TLabel", font=("Arial", 12, "bold"))
        self.style.configure("Critical.TLabel", foreground="#ff4444", font=("Arial", 10, "bold"))
        self.style.configure("High.TLabel", foreground="#ff8800", font=("Arial", 10, "bold"))
        self.style.configure("Medium.TLabel", foreground="#ffcc00", font=("Arial", 10, "bold"))
        self.style.configure("Low.TLabel", foreground="#88cc00", font=("Arial", 10, "bold"))
        self.style.configure("Info.TLabel", foreground="#0088ff", font=("Arial", 10, "bold"))
        
        # Application state
        self.scanning = False
        self.scanner = None
        self.log_queue = queue.Queue()
        self.vulnerabilities = []
        
        self.setup_ui()
        self.setup_logging()
        
    def setup_ui(self):
        """Setup the main UI components"""
        # Create main frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Setup tabs
        self.setup_scan_tab()
        self.setup_results_tab()
        self.setup_log_tab()
        self.setup_settings_tab()
        
        # Status bar
        self.setup_status_bar(main_frame)
        
    def setup_scan_tab(self):
        """Setup the scan configuration tab"""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="Scan Configuration")
        
        # Banner
        banner_frame = ttk.Frame(scan_frame)
        banner_frame.pack(fill=tk.X, padx=5, pady=5)
        
        banner_text = tk.Text(banner_frame, height=6, width=80, font=("Courier", 9))
        banner_text.pack(fill=tk.X)
        banner_text.insert("1.0", BANNER)
        banner_text.config(state=tk.DISABLED)
        
        # Target configuration
        target_frame = ttk.LabelFrame(scan_frame, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.target_url = tk.StringVar(value="https://example.com")
        ttk.Entry(target_frame, textvariable=self.target_url, width=50).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Scan limits
        limits_frame = ttk.LabelFrame(scan_frame, text="Scan Limits", padding=10)
        limits_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(limits_frame, text="Max Pages:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.max_pages = tk.IntVar(value=50)
        ttk.Spinbox(limits_frame, from_=1, to=1000, textvariable=self.max_pages, width=10).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(limits_frame, text="Request Delay (s):").grid(row=0, column=2, sticky=tk.W, padx=(20,0), pady=2)
        self.request_delay = tk.DoubleVar(value=0.5)
        ttk.Spinbox(limits_frame, from_=0.1, to=10.0, increment=0.1, textvariable=self.request_delay, width=10).grid(row=0, column=3, sticky=tk.W, pady=2)
        
        ttk.Label(limits_frame, text="Workers:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.workers = tk.IntVar(value=5)
        ttk.Spinbox(limits_frame, from_=1, to=20, textvariable=self.workers, width=10).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(limits_frame, text="Timeout (s):").grid(row=1, column=2, sticky=tk.W, padx=(20,0), pady=2)
        self.timeout = tk.IntVar(value=15)
        ttk.Spinbox(limits_frame, from_=5, to=60, textvariable=self.timeout, width=10).grid(row=1, column=3, sticky=tk.W, pady=2)
        
        # Security settings
        security_frame = ttk.LabelFrame(scan_frame, text="Security Settings", padding=10)
        security_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.verify_ssl = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Verify SSL Certificates", variable=self.verify_ssl).grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.obey_robots = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Obey robots.txt", variable=self.obey_robots).grid(row=0, column=1, sticky=tk.W, padx=(20,0), pady=2)
        
        # Authentication
        auth_frame = ttk.LabelFrame(scan_frame, text="Authentication", padding=10)
        auth_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(auth_frame, text="Auth Token:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.auth_token = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.auth_token, width=50, show="*").grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(auth_frame, text="Cookies:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.cookies = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.cookies, width=50).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Advanced settings
        advanced_frame = ttk.LabelFrame(scan_frame, text="Advanced Settings", padding=10)
        advanced_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(advanced_frame, text="Exclude Paths:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.exclude_paths = tk.StringVar()
        ttk.Entry(advanced_frame, textvariable=self.exclude_paths, width=50).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Label(advanced_frame, text="(comma-separated, e.g., /admin,/api)").grid(row=0, column=2, sticky=tk.W, padx=(5,0), pady=2)
        
        ttk.Label(advanced_frame, text="Custom Headers:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.headers = tk.StringVar()
        ttk.Entry(advanced_frame, textvariable=self.headers, width=50).grid(row=1, column=1, sticky=tk.W, pady=2)
        ttk.Label(advanced_frame, text="(format: Header1:Value1;Header2:Value2)").grid(row=1, column=2, sticky=tk.W, padx=(5,0), pady=2)
        
        # Control buttons
        button_frame = ttk.Frame(scan_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0,10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0,10))
        
        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT)
        
    def setup_results_tab(self):
        """Setup the results display tab"""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Scan Results")
        
        # Summary frame
        summary_frame = ttk.LabelFrame(results_frame, text="Scan Summary", padding=10)
        summary_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Summary stats
        stats_frame = ttk.Frame(summary_frame)
        stats_frame.pack(fill=tk.X)
        
        self.summary_labels = {}
        severities = ["Critical", "High", "Medium", "Low", "Info", "Total"]
        
        for i, severity in enumerate(severities):
            ttk.Label(stats_frame, text=f"{severity}:").grid(row=0, column=i*2, sticky=tk.W, padx=(10,5))
            label = ttk.Label(stats_frame, text="0", font=("Arial", 12, "bold"))
            label.grid(row=0, column=i*2+1, sticky=tk.W, padx=(0,20))
            self.summary_labels[severity] = label
        
        # Results treeview
        tree_frame = ttk.LabelFrame(results_frame, text="Vulnerabilities", padding=10)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview with scrollbar
        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.results_tree = ttk.Treeview(
            tree_frame,
            columns=("Severity", "Type", "URL", "Description", "Confidence"),
            show="headings",
            yscrollcommand=tree_scroll.set
        )
        tree_scroll.config(command=self.results_tree.yview)
        
        # Configure columns
        self.results_tree.heading("Severity", text="Severity")
        self.results_tree.heading("Type", text="Type")
        self.results_tree.heading("URL", text="URL")
        self.results_tree.heading("Description", text="Description")
        self.results_tree.heading("Confidence", text="Confidence")
        
        self.results_tree.column("Severity", width=80)
        self.results_tree.column("Type", width=150)
        self.results_tree.column("URL", width=200)
        self.results_tree.column("Description", width=300)
        self.results_tree.column("Confidence", width=80)
        
        self.results_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind double-click event
        self.results_tree.bind("<Double-1>", self.show_vulnerability_details)
        
        # Results actions
        action_frame = ttk.Frame(results_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(action_frame, text="Generate Text Report", 
                  command=lambda: self.generate_report("text")).pack(side=tk.LEFT, padx=(0,10))
        ttk.Button(action_frame, text="Generate JSON Report", 
                  command=lambda: self.generate_report("json")).pack(side=tk.LEFT, padx=(0,10))
        ttk.Button(action_frame, text="Generate HTML Report", 
                  command=lambda: self.generate_report("html")).pack(side=tk.LEFT, padx=(0,10))
        ttk.Button(action_frame, text="Clear Results", 
                  command=self.clear_results).pack(side=tk.LEFT)
        
    def setup_log_tab(self):
        """Setup the logging tab"""
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Scan Log")
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=30,
            font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
    def setup_settings_tab(self):
        """Setup the settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        
        # Output settings
        output_frame = ttk.LabelFrame(settings_frame, text="Output Settings", padding=10)
        output_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(output_frame, text="Report Directory:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.output_dir = tk.StringVar(value="reports")
        ttk.Entry(output_frame, textvariable=self.output_dir, width=50).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Button(output_frame, text="Browse", command=self.browse_output_dir).grid(row=0, column=2, sticky=tk.W, padx=(5,0), pady=2)
        
        # Vulnerability types to test
        vuln_frame = ttk.LabelFrame(settings_frame, text="Vulnerability Tests", padding=10)
        vuln_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.test_vulnerabilities = {
            "XSS": tk.BooleanVar(value=True),
            "SQLi": tk.BooleanVar(value=True),
            "CSRF": tk.BooleanVar(value=True),
            "Open Redirect": tk.BooleanVar(value=True),
            "Path Traversal": tk.BooleanVar(value=True),
            "Information Disclosure": tk.BooleanVar(value=True)
        }
        
        row, col = 0, 0
        for vuln_name, var in self.test_vulnerabilities.items():
            ttk.Checkbutton(vuln_frame, text=vuln_name, variable=var).grid(
                row=row, column=col, sticky=tk.W, pady=2, padx=10
            )
            col += 1
            if col > 2:
                col = 0
                row += 1
        
    def setup_status_bar(self, parent):
        """Setup the status bar"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_label.pack(fill=tk.X, ipady=2)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            status_frame, 
            variable=self.progress_var, 
            mode='determinate'
        )
        self.progress_bar.pack(fill=tk.X, pady=(2,0))
        
    def setup_logging(self):
        """Setup logging from scanner to GUI"""
        self.after(100, self.process_log_queue)
        
    def process_log_queue(self):
        """Process log messages from the queue"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, message + "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_log_queue)
    
    def log_message(self, message):
        """Add message to log queue"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put(f"[{timestamp}] {message}")
    
    def clear_log(self):
        """Clear the log text"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def clear_results(self):
        """Clear scan results"""
        self.results_tree.delete(*self.results_tree.get_children())
        for severity in self.summary_labels:
            self.summary_labels[severity].config(text="0")
        self.vulnerabilities.clear()
    
    def browse_output_dir(self):
        """Browse for output directory"""
        directory = filedialog.askdirectory(initialdir=self.output_dir.get())
        if directory:
            self.output_dir.set(directory)
    
    def get_scan_config(self):
        """Create ScanConfig from GUI inputs"""
        # Parse cookies
        cookies = None
        if self.cookies.get():
            cookies = {}
            for pair in self.cookies.get().split(';'):
                if '=' in pair:
                    key, value = pair.strip().split('=', 1)
                    cookies[key] = value
        
        # Parse headers
        headers = None
        if self.headers.get():
            headers = {}
            for header_pair in self.headers.get().split(';'):
                if ':' in header_pair:
                    key, value = header_pair.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # Parse exclude paths
        exclude_paths = None
        if self.exclude_paths.get():
            exclude_paths = [path.strip() for path in self.exclude_paths.get().split(',')]
        
        return ScanConfig(
            target_url=self.target_url.get(),
            max_pages=self.max_pages.get(),
            request_delay=self.request_delay.get(),
            verify_ssl=self.verify_ssl.get(),
            obey_robots=self.obey_ssl.get(),
            workers=self.workers.get(),
            timeout=self.timeout.get(),
            auth_token=self.auth_token.get() or None,
            cookies=cookies,
            headers=headers,
            exclude_paths=exclude_paths,
            verbose=True
        )
    
    def start_scan(self):
        """Start the vulnerability scan in a separate thread"""
        if not self.target_url.get().startswith(('http://', 'https://')):
            messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
            return
        
        # Show authorization warning
        if not messagebox.askyesno(
            "Authorization Required", 
            "⚠️ CRITICAL WARNING:\n\n"
            "• Scanning without authorization is ILLEGAL\n"
            "• You may face criminal prosecution\n"
            "• Only scan systems you own or have written permission to test\n"
            "• Ensure you have a signed authorization letter\n\n"
            "Do you have EXPLICIT written AUTHORIZATION to scan this target?"
        ):
            return
        
        # Disable scan button, enable stop button
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.scanning = True
        
        # Clear previous results
        self.clear_results()
        self.clear_log()
        
        # Update status
        self.status_var.set("Initializing scan...")
        self.progress_var.set(0)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()
    
    def run_scan(self):
        """Run the scan in a background thread"""
        try:
            config = self.get_scan_config()
            self.scanner = VulnerabilityScanner(config)
            
            # Override scanner's logger to use our GUI logging
            original_log = self.scanner.logger.info
            def gui_log(message):
                original_log(message)
                self.log_message(message)
            self.scanner.logger.info = gui_log
            
            # Run the scan
            self.vulnerabilities = self.scanner.scan()
            
            # Update GUI with results
            self.after(0, self.scan_completed)
            
        except Exception as e:
            self.after(0, lambda: self.scan_failed(str(e)))
    
    def scan_completed(self):
        """Handle scan completion"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Scan completed")
        self.progress_var.set(100)
        
        # Update results
        self.update_results_display()
        
        # Show completion message
        messagebox.showinfo("Scan Complete", 
                           f"Scan completed!\nFound {len(self.vulnerabilities)} vulnerabilities.")
    
    def scan_failed(self, error_message):
        """Handle scan failure"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Scan failed")
        
        messagebox.showerror("Scan Failed", f"The scan failed with error:\n{error_message}")
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanner and self.scanning:
            self.scanner.stop_scan()
            self.status_var.set("Stopping scan...")
            self.stop_button.config(state=tk.DISABLED)
    
    def update_results_display(self):
        """Update the results treeview with vulnerabilities"""
        # Clear existing results
        self.results_tree.delete(*self.results_tree.get_children())
        
        # Count vulnerabilities by severity
        severity_count = {
            "Critical": 0, "High": 0, "Medium": 0, 
            "Low": 0, "Info": 0, "Total": len(self.vulnerabilities)
        }
        
        # Add vulnerabilities to treeview
        for vuln in self.vulnerabilities:
            # Update counts
            severity_count[vuln.severity_level] += 1
            
            # Add to treeview
            item_id = self.results_tree.insert(
                "", 
                tk.END, 
                values=(
                    vuln.severity_level,
                    vuln.vuln_type,
                    vuln.url,
                    vuln.description,
                    vuln.confidence
                ),
                tags=(vuln.severity_level,)
            )
            
            # Store vulnerability object reference
            self.results_tree.set(item_id, "vuln_object", vuln)
        
        # Update summary labels
        for severity, count in severity_count.items():
            self.summary_labels[severity].config(text=str(count))
            
            # Color code the severity labels
            if severity in ["Critical", "High", "Medium", "Low", "Info"]:
                label = self.summary_labels[severity]
                label.config(style=f"{severity}.TLabel")
        
        # Configure treeview tags for coloring
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            color = {
                "Critical": "#ff4444",
                "High": "#ff8800", 
                "Medium": "#ffcc00",
                "Low": "#88cc00",
                "Info": "#0088ff"
            }[severity]
            self.results_tree.tag_configure(severity, background=color, foreground="white")
    
    def show_vulnerability_details(self, event):
        """Show detailed vulnerability information"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        vuln = self.results_tree.set(item, "vuln_object")
        
        if not vuln:
            return
        
        # Create details window
        details_window = tk.Toplevel(self)
        details_window.title(f"Vulnerability Details - {vuln.vuln_type}")
        details_window.geometry("600x500")
        details_window.transient(self)
        details_window.grab_set()
        
        # Create main frame
        main_frame = ttk.Frame(details_window, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Severity header
        severity_color = {
            "Critical": "#ff4444", "High": "#ff8800", "Medium": "#ffcc00",
            "Low": "#88cc00", "Info": "#0088ff"
        }[vuln.severity_level]
        
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0,10))
        
        severity_label = tk.Label(
            header_frame, 
            text=f" {vuln.severity_level} ",
            background=severity_color,
            foreground="white",
            font=("Arial", 12, "bold"),
            relief=tk.RAISED,
            border=2
        )
        severity_label.pack(side=tk.LEFT, padx=(0,10))
        
        type_label = ttk.Label(
            header_frame, 
            text=vuln.vuln_type,
            font=("Arial", 12, "bold")
        )
        type_label.pack(side=tk.LEFT)
        
        # Details in a labeled frame
        details_frame = ttk.LabelFrame(main_frame, text="Vulnerability Details", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollable text for details
        details_text = scrolledtext.ScrolledText(
            details_frame, 
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        details_text.pack(fill=tk.BOTH, expand=True)
        
        # Format details
        details_content = f"""
URL: {vuln.url}

Description:
{vuln.description}

Severity: {vuln.severity_level} (Score: {vuln.severity_score})
Confidence: {vuln.confidence}

Evidence:
{vuln.evidence}

Remediation:
{vuln.remediation}

Detected: {datetime.fromtimestamp(vuln.timestamp).strftime('%Y-%m-%d %H:%M:%S')}
"""
        details_text.insert("1.0", details_content)
        details_text.config(state=tk.DISABLED)
        
        # Close button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10,0))
        
        ttk.Button(button_frame, text="Close", 
                  command=details_window.destroy).pack(side=tk.RIGHT)
    
    def generate_report(self, report_type):
        """Generate vulnerability report"""
        if not self.scanner:
            messagebox.showwarning("Warning", "No scan results available to generate report.")
            return
        
        if not self.vulnerabilities:
            messagebox.showinfo("Information", "No vulnerabilities found to report.")
            return
        
        try:
            output_dir = self.output_dir.get()
            
            if report_type == "text":
                report_path = self.scanner.generate_text_report(output_dir)
            elif report_type == "json":
                report_path = self.scanner.generate_json_report(output_dir)
            elif report_type == "html":
                report_path = self.scanner.generate_html_report(output_dir)
            else:
                messagebox.showerror("Error", f"Unknown report type: {report_type}")
                return
            
            if report_path:
                messagebox.showinfo("Success", f"Report generated successfully:\n{report_path}")
            else:
                messagebox.showerror("Error", "Failed to generate report.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")


class RedirectLogger:
    """Redirect scanner logs to GUI"""
    
    def __init__(self, gui_app):
        self.gui_app = gui_app
    
    def write(self, message):
        if message.strip():
            self.gui_app.log_message(message.strip())
    
    def flush(self):
        pass


def main():
    """Main entry point for GUI application"""
    try:
        # Create and run GUI
        app = ScannerGUI()
        
        # Redirect stdout to GUI logging
        sys.stdout = RedirectLogger(app)
        sys.stderr = RedirectLogger(app)
        
        app.mainloop()
        
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Failed to start application: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()