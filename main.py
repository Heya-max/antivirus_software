"""
Antivirus Software - Main Application
A comprehensive antivirus with real-time protection, malware detection, and quarantine management
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import os
import sys
from scanner import MalwareScanner
from quarantine import QuarantineManager
from real_time_monitor import RealTimeMonitor
from utils import get_system_info, format_size, get_timestamp, get_severity_color, get_threat_icon
import signature_db as sig_db


class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Guardian Antivirus")
        self.root.geometry("1000x700")
        self.root.configure(bg="#1a1a2e")
        
        # Initialize components
        self.scanner = MalwareScanner()
        self.quarantine = QuarantineManager()
        self.monitor = RealTimeMonitor()
        
        # State variables
        self.scanning = False
        self.scan_thread = None
        self.scan_results = []
        
        # Setup UI
        self.setup_styles()
        self.create_header()
        self.create_navigation()
        self.create_content_area()
        self.create_status_bar()
        
        # Start real-time monitoring by default
        self.toggle_realtime_protection()
    
    def setup_styles(self):
        """Setup custom styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure custom colors
        style.configure("Header.TLabel", background="#1a1a2e", foreground="#00d9ff", font=("Arial", 16, "bold"))
        style.configure("Nav.TButton", background="#16213e", foreground="#ffffff", font=("Arial", 10), padding=10)
        style.configure("Action.TButton", background="#0f3460", foreground="#ffffff", font=("Arial", 11, "bold"), padding=10)
        style.map("Action.TButton", background=[("active", "#e94560")])
        
        style.configure("Card.TFrame", background="#16213e", relief="flat", borderwidth=0)
        style.configure("Content.TFrame", background="#1a1a2e")
        style.configure("Status.TLabel", background="#1a1a2e", foreground="#888888")
        
    def create_header(self):
        """Create header with logo and title"""
        header = tk.Frame(self.root, bg="#16213e", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        # Logo
        logo_label = tk.Label(header, text="🛡️", font=("Arial", 40), bg="#16213e")
        logo_label.pack(side="left", padx=20)
        
        # Title
        title_frame = tk.Frame(header, bg="#16213e")
        title_frame.pack(side="left", fill="y", pady=15)
        
        title = tk.Label(title_frame, text="Guardian Antivirus", font=("Arial", 20, "bold"), 
                        bg="#16213e", fg="#00d9ff")
        title.pack(anchor="w")
        
        subtitle = tk.Label(title_frame, text="Real-time Protection & Security", 
                          font=("Arial", 10), bg="#16213e", fg="#888888")
        subtitle.pack(anchor="w")
        
        # Status indicator
        self.status_indicator = tk.Label(header, text="● Protected", font=("Arial", 12, "bold"),
                                        bg="#16213e", fg="#00ff88")
        self.status_indicator.pack(side="right", padx=20)
    
    def create_navigation(self):
        """Create navigation sidebar"""
        nav_frame = tk.Frame(self.root, bg="#16213e", width=200)
        nav_frame.pack(side="left", fill="y")
        nav_frame.pack_propagate(False)
        
        # Navigation buttons
        self.nav_buttons = {}
        
        nav_items = [
            ("🏠 Dashboard", self.show_dashboard),
            ("🔍 Scanner", self.show_scanner),
            ("🚫 Quarantine", self.show_quarantine),
            ("🛡️ Real-time Protection", self.show_realtime),
            ("📊 Scan History", self.show_history),
            ("ℹ️ System Info", self.show_system_info)
        ]
        
        for i, (text, command) in enumerate(nav_items):
            btn = tk.Button(nav_frame, text=text, command=command, 
                          bg="#1a1a2e" if i > 0 else "#0f3460",
                          fg="#ffffff", font=("Arial", 11), bd=0, pady=15,
                          activebackground="#e94560", activeforeground="#ffffff",
                          anchor="w", padx=20)
            btn.pack(fill="x")
            self.nav_buttons[text] = btn
        
        # Bottom - Quit button
        quit_btn = tk.Button(nav_frame, text="❌ Exit", command=self.quit_app,
                            bg="#e94560", fg="#ffffff", font=("Arial", 11), bd=0, pady=15,
                            anchor="w", padx=20)
        quit_btn.pack(side="bottom", fill="x", pady=10)
    
    def create_content_area(self):
        """Create main content area"""
        self.content_frame = tk.Frame(self.root, bg="#1a1a2e")
        self.content_frame.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        
        # Show dashboard by default
        self.show_dashboard()
    
    def create_status_bar(self):
        """Create status bar"""
        status_frame = tk.Frame(self.root, bg="#16213e", height=30)
        status_frame.pack(side="bottom", fill="x")
        
        self.status_label = tk.Label(status_frame, text="Ready", bg="#16213e", fg="#888888", font=("Arial", 9))
        self.status_label.pack(side="left", padx=10)
        
        self.scan_progress = ttk.Progressbar(status_frame, mode="indeterminate", length=200)
        
        # Clock
        self.clock_label = tk.Label(status_frame, text="", bg="#16213e", fg="#888888", font=("Arial", 9))
        self.clock_label.pack(side="right", padx=10)
        self.update_clock()
    
    def update_clock(self):
        """Update clock in status bar"""
        from datetime import datetime
        self.clock_label.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self.update_clock)
    
    def clear_content(self):
        """Clear content frame"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    # ==================== VIEWS ====================
    
    def show_dashboard(self):
        """Show dashboard view"""
        self.clear_content()
        
        # Dashboard title
        title = tk.Label(self.content_frame, text="Dashboard", font=("Arial", 24, "bold"),
                        bg="#1a1a2e", fg="#00d9ff")
        title.pack(anchor="w", pady=(0, 20))
        
        # Stats cards
        stats_frame = tk.Frame(self.content_frame, bg="#1a1a2e")
        stats_frame.pack(fill="x", pady=10)
        
        # Get stats
        summary = self.scanner.get_scan_summary()
        quarantine_count = self.quarantine.get_quarantine_count()
        monitor_status = self.monitor.get_status()
        
        # Card 1 - Protection Status
        self.create_stat_card(stats_frame, "🛡️", "Protection Status",
                             "Active" if monitor_status['monitoring'] else "Inactive",
                             "#00ff88" if monitor_status['monitoring'] else "#e94560",
                             0)
        
        # Card 2 - Threats Blocked
        self.create_stat_card(stats_frame, "🚫", "Threats Blocked",
                             str(summary['threats_detected']),
                             "#e94560", 1)
        
        # Card 3 - Files Scanned
        self.create_stat_card(stats_frame, "🔍", "Files Scanned",
                             str(summary['total_files']),
                             "#00d9ff", 2)
        
        # Card 4 - Quarantined
        self.create_stat_card(stats_frame, "📦", "Quarantined Files",
                             str(quarantine_count),
                             "#ffc107", 3)
        
        # Quick Actions
        actions_frame = tk.LabelFrame(self.content_frame, text="Quick Actions", 
                                     bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        actions_frame.pack(fill="x", pady=20)
        
        # Action buttons
        btn_frame = tk.Frame(actions_frame, bg="#16213e")
        btn_frame.pack(fill="x")
        
        quick_actions = [
            ("⚡ Quick Scan", self.quick_scan),
            ("🔎 Full Scan", self.full_scan),
            ("🗑️ Clear Quarantine", self.clear_quarantine),
            ("🔄 Update Definitions", self.update_definitions)
        ]
        
        for i, (text, command) in enumerate(quick_actions):
            btn = tk.Button(btn_frame, text=text, command=command,
                          bg="#0f3460", fg="#ffffff", font=("Arial", 11),
                          bd=0, padx=20, pady=10, activebackground="#e94560",
                          cursor="hand2")
            btn.pack(side="left", padx=5, pady=5)
        
        # Recent Alerts
        alerts_frame = tk.LabelFrame(self.content_frame, text="Recent Alerts",
                                     bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        alerts_frame.pack(fill="both", expand=True, pady=20)
        
        alerts = self.monitor.get_alerts(5)
        if alerts:
            for alert in alerts:
                alert_text = f"[{alert['timestamp']}] {alert['type']}: {alert['message']}"
                alert_label = tk.Label(alerts_frame, text=alert_text, bg="#16213e", fg="#888888",
                                      font=("Arial", 9), anchor="w")
                alert_label.pack(fill="x", pady=2)
        else:
            no_alerts = tk.Label(alerts_frame, text="No recent alerts", bg="#16213e",
                               fg="#888888", font=("Arial", 10))
            no_alerts.pack(pady=20)
    
    def create_stat_card(self, parent, icon, title, value, color, column):
        """Create a stat card widget"""
        card = tk.Frame(parent, bg="#16213e", relief="flat", bd=0)
        card.grid(row=0, column=column, padx=10, pady=5, sticky="nsew")
        card.grid_propagate(False)
        card.config(width=180, height=120)
        
        # Icon
        icon_label = tk.Label(card, text=icon, font=("Arial", 30), bg="#16213e")
        icon_label.pack(pady=(15, 5))
        
        # Title
        title_label = tk.Label(card, text=title, font=("Arial", 10), bg="#16213e", fg="#888888")
        title_label.pack()
        
        # Value
        value_label = tk.Label(card, text=value, font=("Arial", 18, "bold"), bg="#16213e", fg=color)
        value_label.pack()
    
    def show_scanner(self):
        """Show scanner view"""
        self.clear_content()
        
        title = tk.Label(self.content_frame, text="File Scanner", font=("Arial", 24, "bold"),
                        bg="#1a1a2e", fg="#00d9ff")
        title.pack(anchor="w", pady=(0, 20))
        
        # Scan options
        options_frame = tk.LabelFrame(self.content_frame, text="Scan Options",
                                     bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        options_frame.pack(fill="x", pady=10)
        
        # Scan type buttons
        scan_types = [
            ("⚡ Quick Scan", self.quick_scan),
            ("🔎 Full Scan", self.full_scan),
            ("📁 Custom Scan", self.custom_scan)
        ]
        
        btn_frame = tk.Frame(options_frame, bg="#16213e")
        btn_frame.pack(fill="x")
        
        for i, (text, command) in enumerate(scan_types):
            btn = tk.Button(btn_frame, text=text, command=command,
                          bg="#0f3460", fg="#ffffff", font=("Arial", 12),
                          bd=0, padx=25, pady=12, activebackground="#e94560",
                          cursor="hand2")
            btn.pack(side="left", padx=5)
        
        # Results area
        results_frame = tk.LabelFrame(self.content_frame, text="Scan Results",
                                     bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        results_frame.pack(fill="both", expand=True, pady=10)
        
        # Treeview for results
        columns = ("File", "Status", "Severity", "Type")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        self.results_tree.heading("File", text="File")
        self.results_tree.heading("Status", text="Status")
        self.results_tree.heading("Severity", text="Severity")
        self.results_tree.heading("Type", text="Threat Type")
        
        self.results_tree.column("File", width=400)
        self.results_tree.column("Status", width=100)
        self.results_tree.column("Severity", width=100)
        self.results_tree.column("Type", width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Action buttons
        action_frame = tk.Frame(self.content_frame, bg="#1a1a2e")
        action_frame.pack(fill="x", pady=10)
        
        tk.Button(action_frame, text="🗑️ Quarantine Selected", command=self.quarantine_selected,
                 bg="#e94560", fg="#ffffff", font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="📋 Copy Path", command=self.copy_selected_path,
                 bg="#0f3460", fg="#ffffff", font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        self.scan_status_label = tk.Label(action_frame, text="", bg="#1a1a2e", fg="#888888")
        self.scan_status_label.pack(side="right", padx=10)
    
    def show_quarantine(self):
        """Show quarantine view"""
        self.clear_content()
        
        title = tk.Label(self.content_frame, text="Quarantine", font=("Arial", 24, "bold"),
                        bg="#1a1a2e", fg="#00d9ff")
        title.pack(anchor="w", pady=(0, 20))
        
        # Info
        count = self.quarantine.get_quarantine_count()
        info_label = tk.Label(self.content_frame, 
                             text=f"Quarantined Files: {count}",
                             bg="#1a1a2e", fg="#888888", font=("Arial", 12))
        info_label.pack(anchor="w", pady=(0, 10))
        
        # Quarantine list
        list_frame = tk.Frame(self.content_frame, bg="#16213e")
        list_frame.pack(fill="both", expand=True, pady=10)
        
        columns = ("Original Path", "Date", "Threat")
        self.quarantine_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20)
        
        self.quarantine_tree.heading("Original Path", text="Original Path")
        self.quarantine_tree.heading("Date", text="Quarantine Date")
        self.quarantine_tree.heading("Threat", text="Threat Type")
        
        self.quarantine_tree.column("Original Path", width=400)
        self.quarantine_tree.column("Date", width=150)
        self.quarantine_tree.column("Threat", width=150)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=scrollbar.set)
        
        self.quarantine_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Load quarantine data
        self.refresh_quarantine_list()
        
        # Action buttons
        action_frame = tk.Frame(self.content_frame, bg="#1a1a2e")
        action_frame.pack(fill="x", pady=10)
        
        tk.Button(action_frame, text="♻️ Restore Selected", command=self.restore_selected,
                 bg="#00ff88", fg="#1a1a2e", font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="🗑️ Delete Selected", command=self.delete_quarantined,
                 bg="#e94560", fg="#ffffff", font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="🗑️ Clear All", command=self.clear_quarantine,
                 bg="#0f3460", fg="#ffffff", font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="right", padx=5)
    
    def refresh_quarantine_list(self):
        """Refresh quarantine list"""
        # Clear existing
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        
        # Add items
        for file_id, data in self.quarantine.list_quarantined_files().items():
            threat = data.get('threat_info', {}).get('type', 'Unknown')
            self.quarantine_tree.insert("", "end", values=(
                data['original_path'],
                data['quarantine_date'][:19],
                threat
            ))
    
    def show_realtime(self):
        """Show real-time protection view"""
        self.clear_content()
        
        title = tk.Label(self.content_frame, text="Real-time Protection", font=("Arial", 24, "bold"),
                        bg="#1a1a2e", fg="#00d9ff")
        title.pack(anchor="w", pady=(0, 20))
        
        # Status card
        status_card = tk.Frame(self.content_frame, bg="#16213e", relief="flat")
        status_card.pack(fill="x", pady=10)
        
        monitor_status = self.monitor.get_status()
        
        status_icon = "🛡️" if monitor_status['monitoring'] else "⚠️"
        status_text = "Protected" if monitor_status['monitoring'] else "Unprotected"
        status_color = "#00ff88" if monitor_status['monitoring'] else "#e94560"
        
        self.realtime_status = tk.Label(status_card, text=f"{status_icon} {status_text}",
                                       font=("Arial", 24, "bold"), bg="#16213e", fg=status_color)
        self.realtime_status.pack(pady=30)
        
        # Toggle button
        self.realtime_btn = tk.Button(status_card, 
                                     text="Disable Protection" if monitor_status['monitoring'] else "Enable Protection",
                                     command=self.toggle_realtime_protection,
                                     bg="#0f3460" if monitor_status['monitoring'] else "#e94560",
                                     fg="#ffffff", font=("Arial", 12), bd=0, padx=25, pady=12,
                                     cursor="hand2")
        self.realtime_btn.pack(pady=(0, 30))
        
        # Protected locations
        locations_frame = tk.LabelFrame(self.content_frame, text="Protected Locations",
                                       bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                       bd=0, padx=20, pady=20)
        locations_frame.pack(fill="x", pady=10)
        
        for path in monitor_status['protected_paths']:
            path_label = tk.Label(locations_frame, text=f"✓ {path}", bg="#16213e", fg="#00ff88",
                                font=("Arial", 10), anchor="w")
            path_label.pack(fill="x", pady=2)
        
        # Alerts log
        alerts_frame = tk.LabelFrame(self.content_frame, text="Recent Alerts",
                                    bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                    bd=0, padx=20, pady=20)
        alerts_frame.pack(fill="both", expand=True, pady=10)
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=10, bg="#1a1a2e",
                                                     fg="#888888", font=("Arial", 9), bd=0)
        self.alerts_text.pack(fill="both", expand=True)
        
        # Load alerts
        alerts = self.monitor.get_alerts(20)
        for alert in alerts:
            self.alerts_text.insert("end", f"[{alert['timestamp']}] {alert['type']}: {alert['message']}\n")
        self.alerts_text.config(state="disabled")
        
        # Clear alerts button
        tk.Button(alerts_frame, text="Clear Alerts", command=self.clear_alerts,
                 bg="#0f3460", fg="#ffffff", font=("Arial", 10), bd=0, padx=15, pady=5,
                 cursor="hand2").pack(anchor="e", pady=(10, 0))
    
    def show_history(self):
        """Show scan history"""
        self.clear_content()
        
        title = tk.Label(self.content_frame, text="Scan History", font=("Arial", 24, "bold"),
                        bg="#1a1a2e", fg="#00d9ff")
        title.pack(anchor="w", pady=(0, 20))
        
        # Summary
        summary = self.scanner.get_scan_summary()
        
        summary_frame = tk.LabelFrame(self.content_frame, text="Statistics",
                                     bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        summary_frame.pack(fill="x", pady=10)
        
        stats_text = f"""
Total Files Scanned: {summary['total_files']}
Clean Files: {summary['clean_files']}
Infected Files: {summary['infected_files']}
Total Threats Detected: {summary['threats_detected']}
        """
        
        stats_label = tk.Label(summary_frame, text=stats_text, bg="#16213e", fg="#ffffff",
                              font=("Arial", 11), justify="left")
        stats_label.pack(anchor="w")
        
        # Recent results
        results_frame = tk.LabelFrame(self.content_frame, text="Recent Scan Results",
                                     bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        results_frame.pack(fill="both", expand=True, pady=10)
        
        columns = ("File", "Status", "Severity")
        self.history_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        self.history_tree.heading("File", text="File")
        self.history_tree.heading("Status", text="Status")
        self.history_tree.heading("Severity", text="Severity")
        
        self.history_tree.column("File", width=500)
        self.history_tree.column("Status", width=150)
        self.history_tree.column("Severity", width=150)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        self.history_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Load results
        for result in self.scanner.scan_results[-50:]:
            status_color = "#00ff88" if result['status'] == 'Clean' else "#e94560"
            self.history_tree.insert("", "end", values=(
                result['file'][:60],
                result['status'],
                result['severity']
            ))
    
    def show_system_info(self):
        """Show system information"""
        self.clear_content()
        
        title = tk.Label(self.content_frame, text="System Information", font=("Arial", 24, "bold"),
                        bg="#1a1a2e", fg="#00d9ff")
        title.pack(anchor="w", pady=(0, 20))
        
        # Info card
        info_frame = tk.LabelFrame(self.content_frame, text="System Details",
                                  bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                  bd=0, padx=20, pady=20)
        info_frame.pack(fill="both", expand=True, pady=10)
        
        info = get_system_info()
        
        info_text = f"""
Operating System: {info['os']} {info['os_release']}
Version: {info['os_version']}
Architecture: {info['architecture']}
Processor: {info['processor']}
Hostname: {info['hostname']}
Python Version: {info['python_version'][:8]}
        """
        
        info_label = tk.Label(info_frame, text=info_text, bg="#16213e", fg="#ffffff",
                             font=("Arial", 11), justify="left")
        info_label.pack(anchor="w", pady=10)
        
        # About section
        about_frame = tk.LabelFrame(self.content_frame, text="About",
                                   bg="#16213e", fg="#ffffff", font=("Arial", 12, "bold"),
                                   bd=0, padx=20, pady=20)
        about_frame.pack(fill="x", pady=10)
        
        about_text = """
🛡️ Guardian Antivirus v1.0

A comprehensive antivirus solution with:
• Real-time protection
• Malware detection and removal
• Quarantine management
• Multiple scan options (Quick, Full, Custom)

Protected against: Viruses, Worms, Trojans, Spyware, Adware, Ransomware
        """
        
        about_label = tk.Label(about_frame, text=about_text, bg="#16213e", fg="#888888",
                              font=("Arial", 10), justify="left")
        about_label.pack(anchor="w")
    
    # ==================== ACTIONS ====================
    
    def toggle_realtime_protection(self):
        """Toggle real-time protection"""
        status = self.monitor.get_status()
        
        if status['monitoring']:
            self.monitor.stop_monitoring()
            self.status_indicator.config(text="● Unprotected", fg="#e94560")
            messagebox.showinfo("Protection", "Real-time protection disabled")
        else:
            self.monitor.start_monitoring()
            self.status_indicator.config(text="● Protected", fg="#00ff88")
            messagebox.showinfo("Protection", "Real-time protection enabled")
        
        # Refresh the view if on realtime page
        self.show_realtime()
    
    def quick_scan(self):
        """Perform quick scan"""
        if self.scanning:
            messagebox.showwarning("Scanning", "A scan is already in progress")
            return
        
        self.scanning = True
        self.scan_progress.pack(side="left", padx=10)
        self.scan_progress.start()
        
        # Show scanner view
        self.show_scanner()
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.scan_status_label.config(text="Scanning...")
        
        def scan_task():
            results = self.scanner.quick_scan()
            self.scan_results = results
            
            self.root.after(0, self.display_scan_results)
        
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()
    
    def full_scan(self):
        """Perform full scan"""
        if self.scanning:
            messagebox.showwarning("Scanning", "A scan is already in progress")
            return
        
        self.scanning = True
        self.scan_progress.pack(side="left", padx=10)
        self.scan_progress.start()
        
        # Show scanner view
        self.show_scanner()
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.scan_status_label.config(text="Full scanning... (this may take a while)")
        
        def scan_task():
            results = self.scanner.full_scan()
            self.scan_results = results
            
            self.root.after(0, self.display_scan_results)
        
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()
    
    def custom_scan(self):
        """Perform custom scan"""
        path = filedialog.askdirectory(title="Select Folder to Scan")
        
        if not path:
            return
        
        if self.scanning:
            messagebox.showwarning("Scanning", "A scan is already in progress")
            return
        
        self.scanning = True
        self.scan_progress.pack(side="left", padx=10)
        self.scan_progress.start()
        
        # Show scanner view
        self.show_scanner()
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.scan_status_label.config(text=f"Scanning {path}...")
        
        def scan_task():
            results = self.scanner.custom_scan(path)
            self.scan_results = results
            
            self.root.after(0, self.display_scan_results)
        
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()
    
    def display_scan_results(self):
        """Display scan results in treeview"""
        # Stop progress
        self.scanning = False
        self.scan_progress.stop()
        self.scan_progress.pack_forget()
        
        # Update status
        summary = self.scanner.get_scan_summary()
        self.scan_status_label.config(
            text=f"Complete: {summary['clean_files']} clean, {summary['infected_files']} threats found"
        )
        
        # Add results to tree
        for result in self.scan_results:
            status = result['status']
            severity = result.get('severity', 'None')
            threat_type = ""
            
            if result['threats']:
                threat_type = result['threats'][0].get('type', 'Unknown')
            
            self.results_tree.insert("", "end", values=(
                result['file'][:60],
                status,
                severity,
                threat_type
            ))
        
        # Show message if threats found
        if summary['infected_files'] > 0:
            messagebox.showwarning("Scan Complete", 
                                  f"Found {summary['infected_files']} threats!\nCheck the results and quarantine them.")
        else:
            messagebox.showinfo("Scan Complete", "No threats found!")
    
    def quarantine_selected(self):
        """Quarantine selected file"""
        selected = self.results_tree.selection()
        
        if not selected:
            messagebox.showwarning("Select File", "Please select a file to quarantine")
            return
        
        for item in selected:
            values = self.results_tree.item(item)['values']
            filepath = values[0]
            
            if values[1] == "Infected":
                result = self.quarantine.quarantine_file(filepath, {'type': values[3]})
                
                if result['success']:
                    self.results_tree.delete(item)
        
        messagebox.showinfo("Quarantine", "Selected file(s) moved to quarantine")
    
    def copy_selected_path(self):
        """Copy selected file path to clipboard"""
        selected = self.results_tree.selection()
        
        if selected:
            values = self.results_tree.item(selected[0])['values']
            filepath = values[0]
            
            self.root.clipboard_clear()
            self.root.clipboard_append(filepath)
            messagebox.showinfo("Copied", "Path copied to clipboard")
    
    def restore_selected(self):
        """Restore selected quarantined file"""
        selected = self.quarantine_tree.selection()
        
        if not selected:
            messagebox.showwarning("Select File", "Please select a file to restore")
            return
        
        for item in selected:
            values = self.quarantine_tree.item(item)['values']
            original_path = values[0]
            
            # Find the file_id
            for file_id, data in self.quarantine.list_quarantined_files().items():
                if data['original_path'] == original_path:
                    result = self.quarantine.restore_file(file_id)
                    
                    if result['success']:
                        self.quarantine_tree.delete(item)
        
        messagebox.showinfo("Restore", "File(s) restored successfully")
    
    def delete_quarantined(self):
        """Delete selected quarantined file permanently"""
        selected = self.quarantine_tree.selection()
        
        if not selected:
            messagebox.showwarning("Select File", "Please select a file to delete")
            return
        
        confirm = messagebox.askyesno("Confirm Delete", 
                                     "Are you sure you want to permanently delete this file?")
        
        if confirm:
            for item in selected:
                values = self.quarantine_tree.item(item)['values']
                original_path = values[0]
                
                for file_id, data in self.quarantine.list_quarantined_files().items():
                    if data['original_path'] == original_path:
                        self.quarantine.delete_quarantined_file(file_id)
                        self.quarantine_tree.delete(item)
            
            messagebox.showinfo("Deleted", "File(s) permanently deleted")
    
    def clear_quarantine(self):
        """Clear all quarantined files"""
        confirm = messagebox.askyesno("Confirm Clear", 
                                      "Are you sure you want to clear all quarantined files?")
        
        if confirm:
            self.quarantine.clear_all_quarantine()
            self.refresh_quarantine_list()
            messagebox.showinfo("Cleared", "Quarantine cleared")
    
    def clear_alerts(self):
        """Clear alerts"""
        self.monitor.clear_alerts()
        self.show_realtime()
        messagebox.showinfo("Cleared", "Alerts cleared")
    
    def update_definitions(self):
        """Update virus definitions (simulated)"""
        messagebox.showinfo("Update", "Virus definitions are up to date!")
    
    def quit_app(self):
        """Quit application"""
        if self.monitor.get_status()['monitoring']:
            self.monitor.stop_monitoring()
        
        self.root.quit()
        self.root.destroy()


def main():
    """Main entry point"""
    root = tk.Tk()
    
    # Set app icon (if available)
    try:
        root.iconbitmap("antivirus.ico")
    except Exception:
        pass
    
    app = AntivirusApp(root)
    
    root.protocol("WM_DELETE_WINDOW", app.quit_app)
    root.mainloop()


if __name__ == "__main__":
    main()
