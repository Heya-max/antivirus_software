"""
Additional Features for Guardian Antivirus
This module adds Scheduled Scans, USB Device Monitoring, and Updates functionality
"""

import tkinter as tk
from tkinter import messagebox
import threading
import signature_db as sig_db


def add_feature_views(app):
    """Add new feature views to the antivirus app"""
    
    def show_scheduled(self):
        """Show scheduled scans view"""
        self.clear_content()
        colors = self.colors
        
        title = tk.Label(self.content_frame, text="Scheduled Scans", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        info_frame = tk.LabelFrame(self.content_frame, text="About Scheduled Scans",
                                 bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                 bd=0, padx=20, pady=20)
        info_frame.pack(fill="x", pady=10)
        
        info_text = "Schedule Automatic Scans\n\nConfigure: Daily, Weekly, Monthly\nThis feature helps keep your system protected."
        
        info_label = tk.Label(info_frame, text=info_text, bg=colors['bg_secondary'], fg=colors['text_secondary'],
                             font=("Arial", 10), justify="left")
        info_label.pack(anchor="w")
        
        placeholder = tk.Label(self.content_frame, text="Coming soon!",
                              bg=colors['bg_primary'], fg=colors['text_secondary'], font=("Arial", 11))
        placeholder.pack(pady=50)
    
    def show_usb(self):
        """Show USB devices view"""
        self.clear_content()
        colors = self.colors
        
        title = tk.Label(self.content_frame, text="USB Devices", font=("Arial", 24, "bold"),
                        bg=colors['bg_primary'], fg=colors['accent'])
        title.pack(anchor="w", pady=(0, 20))
        
        info_frame = tk.LabelFrame(self.content_frame, text="USB Device Protection",
                                 bg=colors['bg_secondary'], fg=colors['text_primary'], font=("Arial", 12, "bold"),
                                 bd=0, padx=20, pady=20)
        info_frame.pack(fill="x", pady=10)
        
        info_text = "USB Device Security\n\nAuto-scan on insertion\nManual scan\nSafe eject"
        
        info_label = tk.Label(info_frame, text=info_text, bg=colors['bg_secondary'], fg=colors['text_secondary'],
                             font=("Arial", 10), justify="left")
        info_label.pack(anchor="w")
        
        placeholder = tk.Label(self.content_frame, text="Coming soon!",
                              bg=colors['bg_primary'], fg=colors['text_secondary'], font=("Arial", 11))
        placeholder.pack(pady=50)
    
    def show_updates(self):
        """Show updates view"""
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
    
    # Add methods to the app class
    app.show_scheduled = show_scheduled.__get__(app, app.__class__)
    app.show_usb = show_usb.__get__(app, app.__class__)
    app.show_updates = show_updates.__get__(app, app.__class__)
    app.do_update_definitions = do_update_definitions.__get__(app, app.__class__)
    app._update_complete = _update_complete.__get__(app, app.__class__)
    
    return app
