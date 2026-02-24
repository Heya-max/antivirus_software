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
from scheduler import ScanScheduler
from usb_monitor import USBMonitor
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
        self.scheduler = ScanScheduler()
        self.usb_monitor = USBMonitor()
        
        # State variables
        self.scanning = False
        self.scan_thread = None
        self.scan_results = []
        
        # Theme variables
        self.is_dark_theme = True
        self.dark_colors = {
            'bg_primary': '#1a1a2e',
            'bg_secondary': '#16213e',
            'bg_tertiary': '#0f3460',
            'accent': '#00d9ff',
            'accent_secondary': '#e94560',
            'success': '#00ff88',
            'warning': '#ffc107',
            'text_primary': '#ffffff',
            'text_secondary': '#888888'
        }
        self.light_colors = {
            'bg_primary': '#f0f0f0',
            'bg_secondary': '#ffffff',
            'bg_tertiary': '#e0e0e0',
            'accent': '#007bff',
            'accent_secondary': '#dc3545',
            'success': '#28a745',
            'warning': '#ffc107',
            'text_primary': '#333333',
            'text_secondary': '#666666'
        }
        self.colors = self.dark_colors
        
        # Store UI element references for theme updates
        self.header_frame = None
        self.nav_frame = None
        self.status_frame = None
        self.content_frame = None
        
        # Setup UI
        self.setup_styles()
        self.create_header()
        self.create_navigation()
        self.create_content_area()
        self.create_status_bar()
        
        # Start real-time monitoring by default
        self.toggle_realtime_protection()
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Header.TLabel", background="#1a1a2e", foreground="#00d9ff", font=("Arial", 16, "bold"))
        style.configure("Nav.TButton", background="#16213e", foreground="#ffffff", font=("Arial", 10), padding=10)
        style.configure("Action.TButton", background="#0f3460", foreground="#ffffff", font=("Arial", 11, "bold"), padding=10)
        style.map("Action.TButton", background=[("active", "#e94560")])
        style.configure("Card.TFrame", background="#16213e", relief="flat", borderwidth=0)
        style.configure("Content.TFrame", background="#1a1a2e")
        style.configure("Status.TLabel", background="#1a1a2e", foreground="#888888")
        
    def create_header(self):
        colors = self.colors
        self.header_frame = tk.Frame(self.root, bg=colors['bg_secondary'], height=80)
        self.header_frame.pack(fill="x")
        self.header_frame.pack_propagate(False)
        
        logo_label = tk.Label(self.header_frame, text="🛡️", font=("Arial", 40), bg=colors['bg_secondary'])
        logo_label.pack(side="left", padx=20)
        
        title_frame = tk.Frame(self.header_frame, bg=colors['bg_secondary'])
        title_frame.pack(side="left", fill="y", pady=15)
        
        title = tk.Label(title_frame, text="Guardian Antivirus", font=("Arial", 20, "bold"), 
                        bg=colors['bg_secondary'], fg=colors['accent'])
        title.pack(anchor="w")
        
        subtitle = tk.Label(title_frame, text="Real-time Protection & Security", 
                          font=("Arial", 10), bg=colors['bg_secondary'], fg=colors['text_secondary'])
        subtitle.pack(anchor="w")
        
        self.theme_btn = tk.Button(self.header_frame, text="🌙", command=self.toggle_theme,
                                   font=("Arial", 16), bg=colors['bg_secondary'], fg=colors['text_primary'],
                                   bd=0, padx=10, cursor="hand2", activebackground=colors['bg_tertiary'])
        self.theme_btn.pack(side="right", padx=5)
        
        self.status_indicator = tk.Label(self.header_frame, text="● Protected", font=("Arial", 12, "bold"),
                                        bg=colors['bg_secondary'], fg=colors['success'])
        self.status_indicator.pack(side="right", padx=20)
    
    def create_navigation(self):
        colors = self.colors
        self.nav_frame = tk.Frame(self.root, bg=colors['bg_secondary'], width=200)
        self.nav_frame.pack(side="left", fill="y")
        self.nav_frame.pack_propagate(False)
        
        self.nav_buttons = {}
        
        nav_items = [
            ("🏠 Dashboard", self.show_dashboard),
            ("🔍 Scanner", self.show_scanner),
            ("🚫 Quarantine", self.show_quarantine),
            ("🛡️ Real-time Protection", self.show_realtime),
            ("📊 Scan History", self.show_history),
            ("📅 Scheduled Scans", self.show_scheduled),
            ("🔌 USB Devices", self.show_usb),
            ("🔄 Updates", self.show_updates),
            ("ℹ️ System Info", self.show_system_info)
        ]
        
        for i, (text, command) in enumerate(nav_items):
            btn = tk.Button(self.nav_frame, text=text, command=command, 
                          bg=colors['bg_tertiary'] if i == 0 else colors['bg_primary'],
                          fg=colors['text_primary'], font=("Arial", 11), bd=0, pady=15,
                          activebackground=colors['accent_secondary'], activeforeground=colors['text_primary'],
                          anchor="w", padx=20)
            btn.pack(fill="x")
            self.nav_buttons[text] = btn
        
        self.quit_btn = tk.Button(self.nav_frame, text="❌ Exit", command=self.quit_app,
                            bg=colors['accent_secondary'], fg=colors['text_primary'], font=("Arial", 11), bd=0, pady=15,
                            anchor="w", padx=20)
        self.quit_btn.pack(side="bottom", fill="x", pady=10)
    
    def create_content_area(self):
        colors = self.colors
        self.content_frame = tk.Frame(self.root, bg=colors['bg_primary'])
        self.content_frame.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        self.show_dashboard()
    
    def create_status_bar(self):
        colors = self.colors
        self.status_frame = tk.Frame(self.root, bg=colors['bg_secondary'], height=30)
        self.status_frame.pack(side="bottom", fill="x")
        
        self.status_label = tk.Label(self.status_frame, text="Ready", bg=colors['bg_secondary'], 
                                    fg=colors['text_secondary'], font=("Arial", 9))
        self.status_label.pack(side="left", padx=10)
        
        self.scan_progress = ttk.Progressbar(self.status_frame, mode="indeterminate", length=200)
        
        self.clock_label = tk.Label(self.status_frame, text="", bg=colors['bg_secondary'], 
                                    fg=colors['text_secondary'], font=("Arial", 9))
        self.clock_label.pack(side="right", padx=10)
        self.update_clock()
    
    def update_clock(self):
        from datetime import datetime
        self.clock_label.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self.update_clock)
    
    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    # ==================== VIEWS ====================
    
    def show_dashboard(self):
        self.clear_content()
        colors = self.colors
        
        title = tk.Label(self.content_frame, text="Dashboard", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        stats_frame = tk.Frame(self.content_frame, bg=colors['bg_primary'])
        stats_frame.pack(fill="x", pady=10)
        
        summary = self.scanner.get_scan_summary()
        quarantine_count = self.quarantine.get_quarantine_count()
        monitor_status = self.monitor.get_status()
        
        self.create_stat_card(stats_frame, "🛡️", "Protection Status",
                             "Active" if monitor_status['monitoring'] else "Inactive",
                             colors['success'] if monitor_status['monitoring'] else colors['accent_secondary'],
                             0)
        
        self.create_stat_card(stats_frame, "🚫", "Threats Blocked",
                             str(summary['threats_detected']),
                             colors['accent_secondary'], 1)
        
        self.create_stat_card(stats_frame, "🔍", "Files Scanned",
                             str(summary['total_files']),
                             colors['accent'], 2)
        
        self.create_stat_card(stats_frame, "📦", "Quarantined Files",
                             str(quarantine_count),
                             colors['warning'], 3)
        
        actions_frame = tk.LabelFrame(self.content_frame, text="Quick Actions", 
                                     bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        actions_frame.pack(fill="x", pady=20)
        
        btn_frame = tk.Frame(actions_frame, bg=colors['bg_secondary'])
        btn_frame.pack(fill="x")
        
        quick_actions = [
            ("⚡ Quick Scan", self.quick_scan),
            ("🔎 Full Scan", self.full_scan),
            ("🗑️ Clear Quarantine", self.clear_quarantine),
            ("🔄 Update Definitions", self.update_definitions)
        ]
        
        for i, (text, command) in enumerate(quick_actions):
            btn = tk.Button(btn_frame, text=text, command=command,
                          bg=colors['bg_tertiary'], fg=colors['text_primary'], font=("Arial", 11),
                          bd=0, padx=20, pady=10, activebackground=colors['accent_secondary'],
                          cursor="hand2")
            btn.pack(side="left", padx=5, pady=5)
        
        alerts_frame = tk.LabelFrame(self.content_frame, text="Recent Alerts",
                                     bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        alerts_frame.pack(fill="both", expand=True, pady=20)
        
        alerts = self.monitor.get_alerts(5)
        if alerts:
            for alert in alerts:
                alert_text = f"[{alert['timestamp']}] {alert['type']}: {alert['message']}"
                alert_label = tk.Label(alerts_frame, text=alert_text, bg=colors['bg_secondary'], 
                                      fg=colors['text_secondary'], font=("Arial", 9), anchor="w")
                alert_label.pack(fill="x", pady=2)
        else:
            no_alerts = tk.Label(alerts_frame, text="No recent alerts", bg=colors['bg_secondary'],
                               fg=colors['text_secondary'], font=("Arial", 10))
            no_alerts.pack(pady=20)
    
    def create_stat_card(self, parent, icon, title, value, color, column):
        colors = self.colors
        card = tk.Frame(parent, bg=colors['bg_secondary'], relief="flat", bd=0)
        card.grid(row=0, column=column, padx=10, pady=5, sticky="nsew")
        card.grid_propagate(False)
        card.config(width=180, height=120)
        
        icon_label = tk.Label(card, text=icon, font=("Arial", 30), bg=colors['bg_secondary'])
        icon_label.pack(pady=(15, 5))
        
        title_label = tk.Label(card, text=title, font=("Arial", 10), bg=colors['bg_secondary'], fg=colors['text_secondary'])
        title_label.pack()
        
        value_label = tk.Label(card, text=value, font=("Arial", 18, "bold"), bg=colors['bg_secondary'], fg=color)
        value_label.pack()
    
    def show_scanner(self):
        self.clear_content()
        colors = self.colors
        
        title = tk.Label(self.content_frame, text="File Scanner", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        options_frame = tk.LabelFrame(self.content_frame, text="Scan Options",
                                     bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        options_frame.pack(fill="x", pady=10)
        
        scan_types = [
            ("⚡ Quick Scan", self.quick_scan),
            ("🔎 Full Scan", self.full_scan),
            ("📁 Custom Scan", self.custom_scan)
        ]
        
        btn_frame = tk.Frame(options_frame, bg=colors['bg_secondary'])
        btn_frame.pack(fill="x")
        
        for i, (text, command) in enumerate(scan_types):
            btn = tk.Button(btn_frame, text=text, command=command,
                          bg=colors['bg_tertiary'], fg=colors['text_primary'], font=("Arial", 12),
                          bd=0, padx=25, pady=12, activebackground=colors['accent_secondary'],
                          cursor="hand2")
            btn.pack(side="left", padx=5)
        
        results_frame = tk.LabelFrame(self.content_frame, text="Scan Results",
                                     bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        results_frame.pack(fill="both", expand=True, pady=10)
        
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
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        action_frame = tk.Frame(self.content_frame, bg=colors['bg_primary'])
        action_frame.pack(fill="x", pady=10)
        
        tk.Button(action_frame, text="🗑️ Quarantine Selected", command=self.quarantine_selected,
                 bg=colors['accent_secondary'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="📋 Copy Path", command=self.copy_selected_path,
                 bg=colors['bg_tertiary'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        self.scan_status_label = tk.Label(action_frame, text="", bg=colors['bg_primary'], fg=colors['text_secondary'])
        self.scan_status_label.pack(side="right", padx=10)
    
    def show_quarantine(self):
        self.clear_content()
        colors = self.colors
        
        title = tk.Label(self.content_frame, text="Quarantine", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        count = self.quarantine.get_quarantine_count()
        info_label = tk.Label(self.content_frame, 
                             text=f"Quarantined Files: {count}",
                             bg=colors['bg_primary'], fg=colors['text_secondary'], font=("Arial", 12))
        info_label.pack(anchor="w", pady=(0, 10))
        
        list_frame = tk.Frame(self.content_frame, bg=colors['bg_secondary'])
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
        
        self.refresh_quarantine_list()
        
        action_frame = tk.Frame(self.content_frame, bg=colors['bg_primary'])
        action_frame.pack(fill="x", pady=10)
        
        tk.Button(action_frame, text="♻️ Restore Selected", command=self.restore_selected,
                 bg=colors['success'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="🗑️ Delete Selected", command=self.delete_quarantined,
                 bg=colors['accent_secondary'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="🗑️ Clear All", command=self.clear_quarantine,
                 bg=colors['bg_tertiary'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="right", padx=5)
    
    def refresh_quarantine_list(self):
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        
        for file_id, data in self.quarantine.list_quarantined_files().items():
            threat = data.get('threat_info', {}).get('type', 'Unknown')
            self.quarantine_tree.insert("", "end", values=(
                data['original_path'],
                data['quarantine_date'][:19],
                threat
            ))
    
    def show_realtime(self):
        self.clear_content()
        colors = self.colors
        
        title = tk.Label(self.content_frame, text="Real-time Protection", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        status_card = tk.Frame(self.content_frame, bg=colors['bg_secondary'], relief="flat")
        status_card.pack(fill="x", pady=10)
        
        monitor_status = self.monitor.get_status()
        
        status_icon = "🛡️" if monitor_status['monitoring'] else "⚠️"
        status_text = "Protected" if monitor_status['monitoring'] else "Unprotected"
        status_color = colors['success'] if monitor_status['monitoring'] else colors['accent_secondary']
        
        self.realtime_status = tk.Label(status_card, text=f"{status_icon} {status_text}",
                                       font=("Arial", 24, "bold"), bg=colors['bg_secondary'], fg=status_color)
        self.realtime_status.pack(pady=30)
        
        self.realtime_btn = tk.Button(status_card, 
                                     text="Disable Protection" if monitor_status['monitoring'] else "Enable Protection",
                                     command=self.toggle_realtime_protection,
                                     bg=colors['bg_tertiary'] if monitor_status['monitoring'] else colors['accent_secondary'],
                                     fg=colors['text_primary'], font=("Arial", 12), bd=0, padx=25, pady=12,
                                     cursor="hand2")
        self.realtime_btn.pack(pady=(0, 30))
        
        locations_frame = tk.LabelFrame(self.content_frame, text="Protected Locations",
                                       bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                       bd=0, padx=20, pady=20)
        locations_frame.pack(fill="x", pady=10)
        
        for path in monitor_status['protected_paths']:
            path_label = tk.Label(locations_frame, text=f"✓ {path}", bg=colors['bg_secondary'], fg=colors['success'],
                                font=("Arial", 10), anchor="w")
            path_label.pack(fill="x", pady=2)
        
        alerts_frame = tk.LabelFrame(self.content_frame, text="Recent Alerts",
                                    bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                    bd=0, padx=20, pady=20)
        alerts_frame.pack(fill="both", expand=True, pady=10)
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=10, bg=colors['bg_primary'],
                                                     fg=colors['text_secondary'], font=("Arial", 9), bd=0)
        self.alerts_text.pack(fill="both", expand=True)
        
        alerts = self.monitor.get_alerts(20)
        for alert in alerts:
            self.alerts_text.insert("end", f"[{alert['timestamp']}] {alert['type']}: {alert['message']}\n")
        self.alerts_text.config(state="disabled")
        
        tk.Button(alerts_frame, text="Clear Alerts", command=self.clear_alerts,
                 bg=colors['bg_tertiary'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=5,
                 cursor="hand2").pack(anchor="e", pady=(10, 0))
    
    def show_history(self):
        self.clear_content()
        colors = self.colors
        
        title = tk.Label(self.content_frame, text="Scan History", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        summary = self.scanner.get_scan_summary()
        
        summary_frame = tk.LabelFrame(self.content_frame, text="Statistics",
                                     bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                     bd=0, padx=20, pady=20)
        summary_frame.pack(fill="x", pady=10)
        
        stats_text = f"""Total Files Scanned: {summary['total_files']}
Clean Files: {summary['clean_files']}
Infected Files: {summary['infected_files']}
Total Threats Detected: {summary['threats_detected']}"""
        
        stats_label = tk.Label(summary_frame, text=stats_text, bg=colors['bg_secondary'], fg=colors['text_primary'],
                              font=("Arial", 11), justify="left")
        stats_label.pack(anchor="w")
        
        results_frame = tk.LabelFrame(self.content_frame, text="Recent Scan Results",
                                     bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
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
        
        for result in self.scanner.scan_results[-50:]:
            self.history_tree.insert("", "end", values=(
                result['file'][:60],
                result['status'],
                result['severity']
            ))
    
    def show_system_info(self):
        self.clear_content()
        colors = self.colors
        
        title = tk.Label(self.content_frame, text="System Information", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        info_frame = tk.LabelFrame(self.content_frame, text="System Details",
                                  bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                  bd=0, padx=20, pady=20)
        info_frame.pack(fill="both", expand=True, pady=10)
        
        info = get_system_info()
        
        info_text = f"""Operating System: {info['os']} {info['os_release']}
Version: {info['os_version']}
Architecture: {info['architecture']}
Processor: {info['processor']}
Hostname: {info['hostname']}
Python Version: {info['python_version'][:8]}"""
        
        info_label = tk.Label(info_frame, text=info_text, bg=colors['bg_secondary'], fg=colors['text_primary'],
                             font=("Arial", 11), justify="left")
        info_label.pack(anchor="w", pady=10)
        
        about_frame = tk.LabelFrame(self.content_frame, text="About",
                                   bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                   bd=0, padx=20, pady=20)
        about_frame.pack(fill="x", pady=10)
        
        about_text = """🛡️ Guardian Antivirus v1.0

A comprehensive antivirus solution with:
• Real-time protection
• Malware detection and removal
• Quarantine management
• Multiple scan options (Quick, Full, Custom)

Protected against: Viruses, Worms, Trojans, Spyware, Adware, Ransomware"""
        
        about_label = tk.Label(about_frame, text=about_text, bg=colors['bg_secondary'], fg=colors['text_secondary'],
                              font=("Arial", 10), justify="left")
        about_label.pack(anchor="w")
    
    # NEW FEATURE VIEWS
    
    def show_scheduled(self):
        self.clear_content()
        colors = self.colors
        title = tk.Label(self.content_frame, text="Scheduled Scans", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        # Create new schedule frame
        create_frame = tk.LabelFrame(self.content_frame, text="Create New Schedule",
                                 bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                 bd=0, padx=20, pady=20)
        create_frame.pack(fill="x", pady=10)
        
        # Scan type selection
        scan_type_frame = tk.Frame(create_frame, bg=colors['bg_secondary'])
        scan_type_frame.pack(fill="x", pady=5)
        tk.Label(scan_type_frame, text="Scan Type:", bg=colors['bg_secondary'], 
                fg=colors['text_primary'], font=("Arial", 10)).pack(side="left")
        self.sched_scan_type = ttk.Combobox(scan_type_frame, values=["Quick Scan", "Full Scan", "Custom Scan"], 
                                            state="readonly", width=15)
        self.sched_scan_type.current(0)
        self.sched_scan_type.pack(side="left", padx=10)
        
        # Frequency selection
        freq_frame = tk.Frame(create_frame, bg=colors['bg_secondary'])
        freq_frame.pack(fill="x", pady=5)
        tk.Label(freq_frame, text="Frequency:", bg=colors['bg_secondary'], 
                fg=colors['text_primary'], font=("Arial", 10)).pack(side="left")
        self.sched_frequency = ttk.Combobox(freq_frame, values=["Daily", "Weekly", "Monthly"], 
                                            state="readonly", width=15)
        self.sched_frequency.current(0)
        self.sched_frequency.pack(side="left", padx=10)
        
        # Time selection
        time_frame = tk.Frame(create_frame, bg=colors['bg_secondary'])
        time_frame.pack(fill="x", pady=5)
        tk.Label(time_frame, text="Time (HH:MM):", bg=colors['bg_secondary'], 
                fg=colors['text_primary'], font=("Arial", 10)).pack(side="left")
        self.sched_time = tk.Entry(time_frame, width=10, font=("Arial", 10))
        self.sched_time.insert(0, "09:00")
        self.sched_time.pack(side="left", padx=10)
        
        # Path selection for custom scan
        path_frame = tk.Frame(create_frame, bg=colors['bg_secondary'])
        path_frame.pack(fill="x", pady=5)
        tk.Label(path_frame, text="Path (for custom):", bg=colors['bg_secondary'], 
                fg=colors['text_primary'], font=("Arial", 10)).pack(side="left")
        self.sched_path = tk.Entry(path_frame, width=30, font=("Arial", 10))
        self.sched_path.insert(0, "C:/")
        self.sched_path.pack(side="left", padx=10)
        tk.Button(path_frame, text="Browse", command=self.browse_sched_path,
                 bg=colors['bg_tertiary'], fg=colors['text_primary'], bd=0, padx=10).pack(side="left")
        
        # Add schedule button
        btn_frame = tk.Frame(create_frame, bg=colors['bg_secondary'])
        btn_frame.pack(fill="x", pady=10)
        tk.Button(btn_frame, text="➕ Add Schedule", command=self.add_schedule,
                 bg=colors['success'], fg=colors['text_primary'], font=("Arial", 11), bd=0, padx=20, pady=8,
                 cursor="hand2").pack(side="left")
        
        # Scheduled scans list
        list_frame = tk.LabelFrame(self.content_frame, text="Active Schedules",
                                 bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                 bd=0, padx=20, pady=20)
        list_frame.pack(fill="both", expand=True, pady=10)
        
        columns = ("Type", "Frequency", "Time", "Next Run", "Status")
        self.sched_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        
        self.sched_tree.heading("Type", text="Scan Type")
        self.sched_tree.heading("Frequency", text="Frequency")
        self.sched_tree.heading("Time", text="Time")
        self.sched_tree.heading("Next Run", text="Next Run")
        self.sched_tree.heading("Status", text="Status")
        
        self.sched_tree.column("Type", width=120)
        self.sched_tree.column("Frequency", width=100)
        self.sched_tree.column("Time", width=80)
        self.sched_tree.column("Next Run", width=150)
        self.sched_tree.column("Status", width=80)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.sched_tree.yview)
        self.sched_tree.configure(yscrollcommand=scrollbar.set)
        
        self.sched_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.refresh_schedules()
        
        # Action buttons
        action_frame = tk.Frame(self.content_frame, bg=colors['bg_primary'])
        action_frame.pack(fill="x", pady=10)
        
        tk.Button(action_frame, text="▶️ Run Now", command=self.run_sched_now,
                 bg=colors['accent'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="⏸️ Toggle", command=self.toggle_sched,
                 bg=colors['bg_tertiary'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="🗑️ Delete", command=self.delete_sched,
                 bg=colors['accent_secondary'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        # Start scheduler if not running
        if not self.scheduler.running:
            self.scheduler.start()
    
    def browse_sched_path(self):
        path = filedialog.askdirectory(title="Select Folder")
        if path:
            self.sched_path.delete(0, tk.END)
            self.sched_path.insert(0, path)
    
    def add_schedule(self):
        scan_type = self.sched_scan_type.get().lower().replace(" scan", "")
        frequency = self.sched_frequency.get().lower()
        time_str = self.sched_time.get()
        path = self.sched_path.get() or "C:/"
        
        if not time_str or ":" not in time_str:
            messagebox.showwarning("Invalid Time", "Please enter time in HH:MM format")
            return
        
        self.scheduler.add_schedule(scan_type, frequency, time_str, path)
        self.refresh_schedules()
        messagebox.showinfo("Success", "Schedule added successfully")
    
    def refresh_schedules(self):
        for item in self.sched_tree.get_children():
            self.sched_tree.delete(item)
        
        for i, sched in enumerate(self.scheduler.get_schedules()):
            status = "✓ Enabled" if sched.enabled else "✗ Disabled"
            next_run = sched.next_run.strftime("%Y-%m-%d %H:%M") if sched.next_run else "N/A"
            self.sched_tree.insert("", "end", values=(
                sched.scan_type.upper(),
                sched.frequency.capitalize(),
                sched.time_str,
                next_run,
                status
            ), tags=(str(i),))
    
    def run_sched_now(self):
        selected = self.sched_tree.selection()
        if not selected:
            messagebox.showwarning("Select Schedule", "Please select a schedule to run")
            return
        
        item = selected[0]
        index = int(self.sched_tree.item(item)['tags'][0])
        
        self.status_label.config(text="Running scheduled scan...")
        def run_task():
            results = self.scheduler.run_now(index)
            self.root.after(0, lambda: self._sched_run_complete(results))
        
        threading.Thread(target=run_task, daemon=True).start()
    
    def _sched_run_complete(self, results):
        self.status_label.config(text="Ready")
        infected = sum(1 for r in results if r.get('status') == 'Infected')
        messagebox.showinfo("Scan Complete", f"Scanned {len(results)} files\nFound {infected} threats")
    
    def toggle_sched(self):
        selected = self.sched_tree.selection()
        if not selected:
            messagebox.showwarning("Select Schedule", "Please select a schedule to toggle")
            return
        
        item = selected[0]
        index = int(self.sched_tree.item(item)['tags'][0])
        self.scheduler.toggle_schedule(index)
        self.refresh_schedules()
    
    def delete_sched(self):
        selected = self.sched_tree.selection()
        if not selected:
            messagebox.showwarning("Select Schedule", "Please select a schedule to delete")
            return
        
        confirm = messagebox.askyesno("Confirm Delete", "Delete this schedule?")
        if confirm:
            item = selected[0]
            index = int(self.sched_tree.item(item)['tags'][0])
            self.scheduler.remove_schedule(index)
            self.refresh_schedules()
            messagebox.showinfo("Deleted", "Schedule deleted")
    
    def show_usb(self):
        self.clear_content()
        colors = self.colors
        title = tk.Label(self.content_frame, text="USB Devices", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        # Settings frame
        settings_frame = tk.LabelFrame(self.content_frame, text="Settings",
                                 bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                 bd=0, padx=20, pady=20)
        settings_frame.pack(fill="x", pady=10)
        
        # Auto-scan toggle
        self.usb_auto_scan_var = tk.BooleanVar(value=self.usb_monitor.scan_on_insert)
        auto_scan_check = tk.Checkbutton(settings_frame, text="Auto-scan on device insertion", 
                                        variable=self.usb_auto_scan_var,
                                        bg=colors['bg_secondary'], fg=colors['text_primary'],
                                        selectcolor=colors['bg_tertiary'],
                                        command=self.toggle_usb_auto_scan)
        auto_scan_check.pack(anchor="w", pady=5)
        
        # Start/Stop monitoring button
        usb_status = self.usb_monitor.get_status()
        self.usb_monitor_btn = tk.Button(settings_frame, 
                                        text="Stop Monitoring" if usb_status['monitoring'] else "Start Monitoring",
                                        command=self.toggle_usb_monitoring,
                                        bg=colors['accent_secondary'] if not usb_status['monitoring'] else colors['bg_tertiary'],
                                        fg=colors['text_primary'], font=("Arial", 11), bd=0, padx=20, pady=8,
                                        cursor="hand2")
        self.usb_monitor_btn.pack(anchor="w", pady=10)
        
        # Connected devices list
        list_frame = tk.LabelFrame(self.content_frame, text="Connected Devices",
                                 bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                 bd=0, padx=20, pady=20)
        list_frame.pack(fill="both", expand=True, pady=10)
        
        columns = ("Drive", "Label", "Size", "Type", "Last Scan")
        self.usb_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        
        self.usb_tree.heading("Drive", text="Drive Letter")
        self.usb_tree.heading("Label", text="Volume Label")
        self.usb_tree.heading("Size", text="Size")
        self.usb_tree.heading("Type", text="Type")
        self.usb_tree.heading("Last Scan", text="Last Scan")
        
        self.usb_tree.column("Drive", width=100)
        self.usb_tree.column("Label", width=150)
        self.usb_tree.column("Size", width=100)
        self.usb_tree.column("Type", width=100)
        self.usb_tree.column("Last Scan", width=150)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.usb_tree.yview)
        self.usb_tree.configure(yscrollcommand=scrollbar.set)
        
        self.usb_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.refresh_usb_devices()
        
        # Action buttons
        action_frame = tk.Frame(self.content_frame, bg=colors['bg_primary'])
        action_frame.pack(fill="x", pady=10)
        
        tk.Button(action_frame, text="Refresh", command=self.refresh_usb_devices,
                 bg=colors['accent'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="Scan Device", command=self.scan_usb_device,
                 bg=colors['bg_tertiary'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(action_frame, text="Safe Eject", command=self.safe_eject_usb,
                 bg=colors['warning'], fg=colors['text_primary'], font=("Arial", 10), bd=0, padx=15, pady=8,
                 cursor="hand2").pack(side="left", padx=5)
        
        # Start USB monitoring if not running
        if not usb_status['monitoring']:
            self.usb_monitor.start_monitoring()
    
    def toggle_usb_auto_scan(self):
        self.usb_monitor.set_auto_scan(self.usb_auto_scan_var.get())
    
    def toggle_usb_monitoring(self):
        status = self.usb_monitor.get_status()
        if status['monitoring']:
            self.usb_monitor.stop_monitoring()
            messagebox.showinfo("USB Monitor", "USB monitoring stopped")
        else:
            self.usb_monitor.start_monitoring()
            messagebox.showinfo("USB Monitor", "USB monitoring started")
        self.show_usb()
    
    def refresh_usb_devices(self):
        for item in self.usb_tree.get_children():
            self.usb_tree.delete(item)
        
        devices = self.usb_monitor.get_connected_devices()
        for device in devices:
            size_gb = device.size / (1024**3) if device.size else 0
            last_scan = device.last_scan.strftime("%Y-%m-%d %H:%M") if device.last_scan else "Never"
            self.usb_tree.insert("", "end", values=(
                device.drive_letter,
                device.label or "Unknown",
                f"{size_gb:.2f} GB",
                device.drive_type.capitalize(),
                last_scan
            ))
    
    def scan_usb_device(self):
        selected = self.usb_tree.selection()
        if not selected:
            messagebox.showwarning("Select Device", "Please select a device to scan")
            return
        
        values = self.usb_tree.item(selected[0])['values']
        drive_letter = values[0]
        
        self.status_label.config(text=f"Scanning {drive_letter}...")
        
        def scan_task():
            result = self.usb_monitor.scan_device(drive_letter)
            self.root.after(0, lambda: self._usb_scan_complete(result))
        
        threading.Thread(target=scan_task, daemon=True).start()
    
    def _usb_scan_complete(self, result):
        self.status_label.config(text="Ready")
        if result.get('success'):
            messagebox.showinfo("Scan Complete", 
                f"Files scanned: {result.get('files_scanned', 0)}\nThreats found: {result.get('threats_found', 0)}")
        else:
            messagebox.showwarning("Scan Failed", result.get('error', 'Unknown error'))
        self.refresh_usb_devices()
    
    def safe_eject_usb(self):
        selected = self.usb_tree.selection()
        if not selected:
            messagebox.showwarning("Select Device", "Please select a device to eject")
            return
        
        values = self.usb_tree.item(selected[0])['values']
        drive_letter = values[0]
        
        result = self.usb_monitor.safe_eject(drive_letter)
        if result.get('success'):
            messagebox.showinfo("Safe Eject", result.get('message'))
            self.refresh_usb_devices()
        else:
            messagebox.showwarning("Eject Failed", result.get('error', 'Could not eject device'))
    
    def show_updates(self):
        self.clear_content()
        colors = self.colors
        title = tk.Label(self.content_frame, text="Updates", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        db_info = sig_db.get_database_info()
        
        info_frame = tk.LabelFrame(self.content_frame, text="Virus Definitions",
                                 bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                 bd=0, padx=20, pady=20)
        info_frame.pack(fill="x", pady=10)
        
        info_text = f"Version: {db_info.get('version', '1.0.0')}\nSignatures: {db_info.get('signature_count', 0)}\nLast Update: {db_info.get('last_update', 'Never')}"
        info_label = tk.Label(info_frame, text=info_text, bg=colors['bg_secondary'], fg=colors['text_primary'],
                             font=("Arial", 11), justify="left")
        info_label.pack(anchor="w")
        
        btn_frame = tk.Frame(self.content_frame, bg=colors['bg_primary'])
        btn_frame.pack(fill="x", pady=20)
        
        tk.Button(btn_frame, text="Check for Updates", command=self.do_update_definitions,
                 bg=colors['accent'], fg=colors['text_primary'], font=("Arial", 12), bd=0, padx=20, pady=12,
                 cursor="hand2").pack(side="left", padx=5)
    
    def do_update_definitions(self):
        self.status_label.config(text="Updating...")
        
        def update_task():
            result = sig_db.update_definitions(force=True)
            self.root.after(0, lambda: self._update_complete(result))
        
        threading.Thread(target=update_task, daemon=True).start()
    
    def _update_complete(self, result):
        self.status_label.config(text="Ready")
        if result.get('success'):
            messagebox.showinfo("Update", result.get('message', 'Updated!'))
        else:
            messagebox.showwarning("Update", result.get('message', 'Failed'))
        self.show_updates()
    
    # ==================== ACTIONS ====================
    
    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        
        if self.is_dark_theme:
            self.colors = self.dark_colors
            self.theme_btn.config(text="🌙")
        else:
            self.colors = self.light_colors
            self.theme_btn.config(text="☀️")
        
        self.apply_theme()
    
    def apply_theme(self):
        colors = self.colors
        self.root.configure(bg=colors['bg_primary'])
        
        if self.header_frame:
            self.header_frame.configure(bg=colors['bg_secondary'])
            for child in self.header_frame.winfo_children():
                try:
                    child.configure(bg=colors['bg_secondary'])
                except:
                    pass
            self.theme_btn.configure(bg=colors['bg_secondary'], fg=colors['text_primary'], 
                                   activebackground=colors['bg_tertiary'])
            self.status_indicator.configure(bg=colors['bg_secondary'], fg=colors['success'])
        
        if self.nav_frame:
            self.nav_frame.configure(bg=colors['bg_secondary'])
            for child in self.nav_frame.winfo_children():
                try:
                    child.configure(bg=colors['bg_secondary'])
                except:
                    pass
            for i, btn in enumerate(self.nav_buttons.values()):
                btn.configure(bg=colors['bg_tertiary'] if i == 0 else colors['bg_primary'],
                             fg=colors['text_primary'],
                             activebackground=colors['accent_secondary'],
                             activeforeground=colors['text_primary'])
            self.quit_btn.configure(bg=colors['accent_secondary'], fg=colors['text_primary'])
        
        if self.status_frame:
            self.status_frame.configure(bg=colors['bg_secondary'])
            self.status_label.configure(bg=colors['bg_secondary'], fg=colors['text_secondary'])
            self.clock_label.configure(bg=colors['bg_secondary'], fg=colors['text_secondary'])
        
        if self.content_frame:
            self.content_frame.configure(bg=colors['bg_primary'])
        
        self.show_dashboard()
    
    def toggle_realtime_protection(self):
        status = self.monitor.get_status()
        colors = self.colors
        
        if status['monitoring']:
            self.monitor.stop_monitoring()
            self.status_indicator.config(text="● Unprotected", fg=colors['accent_secondary'])
            messagebox.showinfo("Protection", "Real-time protection disabled")
        else:
            self.monitor.start_monitoring()
            self.status_indicator.config(text="● Protected", fg=colors['success'])
            messagebox.showinfo("Protection", "Real-time protection enabled")
        
        self.show_realtime()
    
    def quick_scan(self):
        if self.scanning:
            messagebox.showwarning("Scanning", "A scan is already in progress")
            return
        
        self.scanning = True
        self.scan_progress.pack(side="left", padx=10)
        self.scan_progress.start()
        
        self.show_scanner()
        
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
        if self.scanning:
            messagebox.showwarning("Scanning", "A scan is already in progress")
            return
        
        self.scanning = True
        self.scan_progress.pack(side="left", padx=10)
        self.scan_progress.start()
        
        self.show_scanner()
        
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
        path = filedialog.askdirectory(title="Select Folder to Scan")
        
        if not path:
            return
        
        if self.scanning:
            messagebox.showwarning("Scanning", "A scan is already in progress")
            return
        
        self.scanning = True
        self.scan_progress.pack(side="left", padx=10)
        self.scan_progress.start()
        
        self.show_scanner()
        
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
        colors = self.colors
        
        self.scanning = False
        self.scan_progress.stop()
        self.scan_progress.pack_forget()
        
        summary = self.scanner.get_scan_summary()
        self.scan_status_label.config(
            text=f"Complete: {summary['clean_files']} clean, {summary['infected_files']} threats found"
        )
        
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
        
        if summary['infected_files'] > 0:
            messagebox.showwarning("Scan Complete", 
                                  f"Found {summary['infected_files']} threats!\nCheck the results and quarantine them.")
        else:
            messagebox.showinfo("Scan Complete", "No threats found!")
    
    def quarantine_selected(self):
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
        selected = self.results_tree.selection()
        
        if selected:
            values = self.results_tree.item(selected[0])['values']
            filepath = values[0]
            
            self.root.clipboard_clear()
            self.root.clipboard_append(filepath)
            messagebox.showinfo("Copied", "Path copied to clipboard")
    
    def restore_selected(self):
        selected = self.quarantine_tree.selection()
        
        if not selected:
            messagebox.showwarning("Select File", "Please select a file to restore")
            return
        
        for item in selected:
            values = self.quarantine_tree.item(item)['values']
            original_path = values[0]
            
            for file_id, data in self.quarantine.list_quarantined_files().items():
                if data['original_path'] == original_path:
                    result = self.quarantine.restore_file(file_id)
                    
                    if result['success']:
                        self.quarantine_tree.delete(item)
        
        messagebox.showinfo("Restore", "File(s) restored successfully")
    
    def delete_quarantined(self):
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
        confirm = messagebox.askyesno("Confirm Clear", 
                                      "Are you sure you want to clear all quarantined files?")
        
        if confirm:
            self.quarantine.clear_all_quarantine()
            self.refresh_quarantine_list()
            messagebox.showinfo("Cleared", "Quarantine cleared")
    
    def clear_alerts(self):
        self.monitor.clear_alerts()
        self.show_realtime()
        messagebox.showinfo("Cleared", "Alerts cleared")
    
    def update_definitions(self):
        self.show_updates()
    
    def quit_app(self):
        if self.monitor.get_status()['monitoring']:
            self.monitor.stop_monitoring()
        
        self.root.quit()
        self.root.destroy()


def main():
    root = tk.Tk()
    
    try:
        root.iconbitmap("antivirus.ico")
    except Exception:
        pass
    
    app = AntivirusApp(root)
    
    root.protocol("WM_DELETE_WINDOW", app.quit_app)
    root.mainloop()


if __name__ == "__main__":
    main()
