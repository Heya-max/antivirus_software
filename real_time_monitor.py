"""
Real-time Protection Monitor
Continuously monitors system for suspicious activity
"""

import os
import time
import threading
import psutil
import datetime
from scanner import MalwareScanner
from signature_db import SUSPICIOUS_EXTENSIONS, MALICIOUS_FILENAMES


class RealTimeMonitor:
    def __init__(self):
        self.scanner = MalwareScanner()
        self.monitoring = False
        self.monitor_thread = None
        self.log_file = "real_time_log.txt"
        self.alerts = []
        self.protected_paths = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            "C:/Windows/System32" if os.name == 'nt' else '/bin'
        ]
        
    def log_event(self, event_type, message):
        """Log an event to file"""
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"[{timestamp}] {event_type}: {message}\n"
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(log_entry)
        except Exception:
            pass
        
        self.alerts.append({
            'timestamp': timestamp,
            'type': event_type,
            'message': message
        })
        
        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
    
    def check_process(self, process):
        """Check if a process is suspicious"""
        try:
            process_info = {
                'name': process.name(),
                'pid': process.pid,
                'status': process.status(),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent()
            }
            
            # Check for suspicious process names
            suspicious_names = ['malware', 'virus', 'trojan', 'keylog', 'inject']
            for name in suspicious_names:
                if name.lower() in process.name().lower():
                    self.log_event("SUSPICIOUS_PROCESS", 
                        f"Suspicious process detected: {process.name()} (PID: {process.pid})")
                    return True
            
            # Check for processes with high CPU/memory
            if process.cpu_percent() > 90:
                self.log_event("HIGH_RESOURCE", 
                    f"High CPU usage: {process.name()} - {process.cpu_percent()}%")
            
            if process.memory_percent() > 80:
                self.log_event("HIGH_MEMORY", 
                    f"High memory usage: {process.name()} - {process.memory_percent()}%")
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        
        return False
    
    def monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        while self.monitoring:
            try:
                for process in psutil.process_iter(['name', 'pid', 'status']):
                    self.check_process(process)
                    
            except Exception as e:
                self.log_event("ERROR", f"Process monitoring error: {str(e)}")
            
            time.sleep(5)  # Check every 5 seconds
    
    def monitor_file_system(self):
        """Monitor file system for new suspicious files"""
        # Track recently created files
        previous_files = {}
        
        while self.monitoring:
            try:
                for path in self.protected_paths:
                    if os.path.exists(path):
                        try:
                            current_files = {}
                            for root, dirs, files in os.walk(path):
                                for filename in files:
                                    filepath = os.path.join(root, filename)
                                    try:
                                        stat = os.stat(filepath)
                                        current_files[filepath] = stat.st_mtime
                                        
                                        # Check if file is new
                                        if filepath not in previous_files:
                                            # New file created
                                            self.check_new_file(filepath)
                                            
                                    except Exception:
                                        pass
                            
                            previous_files = current_files
                            
                        except Exception:
                            pass
                            
            except Exception as e:
                self.log_event("ERROR", f"File system monitoring error: {str(e)}")
            
            time.sleep(10)  # Check every 10 seconds
    
    def check_new_file(self, filepath):
        """Check if a new file is suspicious"""
        try:
            # Check file extension
            ext = os.path.splitext(filepath)[1].lower()
            if ext in SUSPICIOUS_EXTENSIONS:
                self.log_event("SUSPICIOUS_FILE", 
                    f"New suspicious file created: {filepath} (extension: {ext})")
                
                # Scan the file
                result = self.scanner.scan_file(filepath)
                if result['status'] == 'Infected':
                    self.log_event("THREAT_DETECTED", 
                        f"Threat detected in new file: {filepath}")
            
            # Check filename
            filename = os.path.basename(filepath).lower()
            if filename in MALICIOUS_FILENAMES:
                self.log_event("MALICIOUS_FILENAME", 
                    f"Known malicious filename detected: {filepath}")
                    
        except Exception as e:
            self.log_event("ERROR", f"Error checking new file: {str(e)}")
    
    def monitor_network(self):
        """Monitor network connections for suspicious activity"""
        while self.monitoring:
            try:
                for conn in psutil.net_connections():
                    if conn.status == 'ESTABLISHED':
                        # Check for suspicious ports
                        suspicious_ports = [4444, 5555, 6666, 31337, 12345]
                        if conn.laddr.port in suspicious_ports:
                            self.log_event("SUSPICIOUS_CONNECTION", 
                                f"Suspicious port connection: {conn.laddr.port}")
                        
                        # Check for connections to known malicious IPs (simplified)
                        # In a real antivirus, this would check against a database
                        
            except Exception as e:
                self.log_event("ERROR", f"Network monitoring error: {str(e)}")
            
            time.sleep(15)  # Check every 15 seconds
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.log_event("INFO", "Real-time protection started")
            
            # Start monitoring threads
            self.monitor_thread = threading.Thread(target=self._run_monitoring, daemon=True)
            self.monitor_thread.start()
            
            return {"success": True, "message": "Real-time protection enabled"}
        else:
            return {"success": False, "message": "Already monitoring"}
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if self.monitoring:
            self.monitoring = False
            self.log_event("INFO", "Real-time protection stopped")
            
            if self.monitor_thread:
                self.monitor_thread.join(timeout=2)
            
            return {"success": True, "message": "Real-time protection disabled"}
        else:
            return {"success": False, "message": "Not currently monitoring"}
    
    def _run_monitoring(self):
        """Run all monitoring tasks"""
        # Start file system monitoring in background
        fs_thread = threading.Thread(target=self.monitor_file_system, daemon=True)
        fs_thread.start()
        
        # Start network monitoring in background
        net_thread = threading.Thread(target=self.monitor_network, daemon=True)
        net_thread.start()
        
        # Main process monitoring
        self.monitor_processes()
    
    def get_alerts(self, count=10):
        """Get recent alerts"""
        return self.alerts[-count:]
    
    def get_status(self):
        """Get monitoring status"""
        return {
            "monitoring": self.monitoring,
            "alerts_count": len(self.alerts),
            "protected_paths": self.protected_paths
        }
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts = []
        return {"success": True, "message": "Alerts cleared"}


# Example usage
if __name__ == "__main__":
    monitor = RealTimeMonitor()
    print("Real-time Protection Monitor")
    print("=" * 50)
    
    # Start monitoring
    print("Starting real-time protection...")
    result = monitor.start_monitoring()
    print(f"Status: {result}")
    
    # Let it run for a bit
    time.sleep(5)
    
    # Check status
    status = monitor.get_status()
    print(f"Status: {status}")
    
    # Get alerts
    alerts = monitor.get_alerts()
    print(f"Alerts: {len(alerts)}")
    
    # Stop monitoring
    print("Stopping monitoring...")
    monitor.stop_monitoring()
    print("Done")
