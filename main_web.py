"""
Guardian Antivirus - WebView Edition
A comprehensive antivirus with modern HTML/CSS interface
"""

import os
import sys
import webview
import threading
import tkinter as tk
from tkinter import filedialog
from scanner import MalwareScanner
from quarantine import QuarantineManager
from real_time_monitor import RealTimeMonitor
from utils import get_system_info


class AntivirusAPI:
    def __init__(self):
        self.scanner = MalwareScanner()
        self.quarantine = QuarantineManager()
        self.monitor = RealTimeMonitor()
        self.scanning = False
        self.scan_thread = None
        
        # Start real-time monitoring by default
        self.monitor.start_monitoring()
    
    def get_scan_summary(self, params=None):
        """Get scan summary statistics"""
        summary = self.scanner.get_scan_summary()
        return {
            'total_files': summary['total_files'],
            'clean_files': summary['clean_files'],
            'infected_files': summary['infected_files'],
            'threats_detected': summary['threats_detected']
        }
    
    def get_quarantine_count(self, params=None):
        """Get count of quarantined files"""
        return self.quarantine.get_quarantine_count()
    
    def get_quarantine_files(self, params=None):
        """Get all quarantined files"""
        return self.quarantine.list_quarantined_files()
    
    def get_realtime_status(self, params=None):
        """Get real-time monitoring status"""
        return self.monitor.get_status()
    
    def get_alerts(self, params=None):
        """Get recent alerts"""
        count = 10
        if params and isinstance(params, dict):
            count = params.get('count', 10)
        return self.monitor.get_alerts(count)
    
    def start_realtime(self, params=None):
        """Start real-time monitoring"""
        return self.monitor.start_monitoring()
    
    def stop_realtime(self, params=None):
        """Stop real-time monitoring"""
        return self.monitor.stop_monitoring()
    
    def quick_scan(self, params=None):
        """Perform quick scan"""
        if self.scanning:
            return []
        
        self.scanning = True
        
        def scan_task():
            results = self.scanner.quick_scan()
            self.scanner.scan_results.extend(results)
            self.scanning = False
        
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()
        
        # Wait for quick scan to complete
        self.scan_thread.join()
        
        return self.scanner.scan_results
    
    def full_scan(self, params=None):
        """Perform full scan"""
        if self.scanning:
            return []
        
        self.scanning = True
        
        def scan_task():
            results = self.scanner.full_scan()
            self.scanner.scan_results.extend(results)
            self.scanning = False
        
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()
        
        # Wait for full scan to complete
        self.scan_thread.join()
        
        return self.scanner.scan_results
    
    def custom_scan(self, params=None):
        """Perform custom scan"""
        path = None
        if params and isinstance(params, dict):
            path = params.get('path')
        
        if self.scanning:
            return []
        
        self.scanning = True
        
        def scan_task():
            results = self.scanner.custom_scan(path) if path else []
            self.scanning = False
        
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()
        
        # Wait for custom scan to complete
        self.scan_thread.join()
        
        return self.scanner.scan_results
    
    def get_scan_results(self, params=None):
        """Get all scan results"""
        return self.scanner.scan_results
    
    def select_folder(self, params=None):
        """Open folder selection dialog"""
        root = tk.Tk()
        root.withdraw()
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        root.destroy()
        return {'path': folder}
    
    def get_system_info(self, params=None):
        """Get system information"""
        return get_system_info()
    
    def clear_quarantine(self, params=None):
        """Clear all quarantine"""
        return self.quarantine.clear_all_quarantine()
    
    def quarantine_file(self, params=None):
        """Quarantine a file by path"""
        if params and isinstance(params, dict):
            filepath = params.get('path')
            threat_info = params.get('threat_info')
            if filepath:
                return self.quarantine.quarantine_file(filepath, threat_info)
        return {"success": False, "error": "Invalid parameters"}
    
    def restore_quarantined(self, params=None):
        """Restore a quarantined file"""
        if params and isinstance(params, dict):
            file_id = params.get('file_id')
            if file_id:
                return self.quarantine.restore_quarantined_file(file_id)
        return {"success": False, "error": "Invalid parameters"}
    
    def delete_quarantined(self, params=None):
        """Permanently delete a quarantined file"""
        if params and isinstance(params, dict):
            file_id = params.get('file_id')
            if file_id:
                return self.quarantine.delete_quarantined_file(file_id)
        return {"success": False, "error": "Invalid parameters"}
    
    def exit_app(self, params=None):
        """Exit the application"""
        if self.monitor.get_status()['monitoring']:
            self.monitor.stop_monitoring()


def get_html_path():
    """Get the path to the HTML file"""
    # Get the directory where the script is located
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller creates a temp folder and stores path there
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    
    html_path = os.path.join(base_path, 'templates', 'index.html')
    
    # If running from source, use relative path
    if not os.path.exists(html_path):
        html_path = os.path.join('templates', 'index.html')
    
    return html_path


def main():
    # Create API instance
    api = AntivirusAPI()
    
    # Get HTML path
    html_path = get_html_path()
    
    print(f"Loading HTML from: {html_path}")
    print(f"HTML exists: {os.path.exists(html_path)}")
    
    # Create webview window with JSAPI
    window = webview.create_window(
        'Guardian Antivirus',
        html_path,
        width=1200,
        height=800,
        min_size=(900, 600),
        background_color='#1a1a2e',
        js_api=api
    )
    
    # Start webview - this exposes api.pywebview
    webview.start(debug=False)


if __name__ == '__main__':
    main()
