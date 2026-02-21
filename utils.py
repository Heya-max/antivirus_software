"""
Utility Functions
Common utility functions for the antivirus software
"""

import os
import sys
import datetime
import platform


def get_system_info():
    """Get system information"""
    return {
        'os': platform.system(),
        'os_version': platform.version(),
        'os_release': platform.release(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'hostname': platform.node(),
        'python_version': sys.version
    }


def format_size(size_bytes):
    """Format bytes to human readable size"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def get_timestamp():
    """Get current timestamp"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_scan_timestamp():
    """Get formatted scan timestamp"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def validate_path(path):
    """Validate if a path exists"""
    return os.path.exists(path)


def is_admin():
    """Check if running with admin privileges"""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_protected_locations():
    """Get list of protected system locations"""
    locations = []
    
    if os.name == 'nt':  # Windows
        locations = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Music"),
            os.path.expanduser("~/Videos"),
            "C:/Windows/System32",
            "C:/Program Files",
            "C:/Program Files (x86)"
        ]
    else:  # Unix-like
        locations = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Music"),
            "/bin",
            "/usr/bin",
            "/etc"
        ]
    
    # Filter to existing paths
    return [loc for loc in locations if os.path.exists(loc)]


def create_log_file(filename="antivirus.log"):
    """Create a log file"""
    try:
        with open(filename, 'a') as f:
            f.write(f"\n=== New Session - {get_timestamp()} ===\n")
        return filename
    except Exception:
        return None


def log_to_file(filename, message):
    """Write message to log file"""
    try:
        with open(filename, 'a') as f:
            f.write(f"[{get_timestamp()}] {message}\n")
    except Exception:
        pass


def get_file_type(filename):
    """Get file type description"""
    import mimetypes
    
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type:
        return mime_type
    
    ext = os.path.splitext(filename)[1].lower()
    ext_types = {
        '.exe': 'Executable',
        '.dll': 'Dynamic Link Library',
        '.sys': 'System File',
        '.doc': 'Document',
        '.docx': 'Document',
        '.pdf': 'PDF Document',
        '.jpg': 'Image',
        '.jpeg': 'Image',
        '.png': 'Image',
        '.gif': 'Image',
        '.zip': 'Archive',
        '.rar': 'Archive',
        '.7z': 'Archive',
        '.mp3': 'Audio',
        '.mp4': 'Video',
        '.avi': 'Video'
    }
    
    return ext_types.get(ext, 'Unknown')


def get_severity_color(severity):
    """Get color for severity level"""
    colors = {
        'Low': '#4CAF50',      # Green
        'Medium': '#FFC107',   # Amber
        'High': '#FF9800',     # Orange
        'Critical': '#F44336', # Red
        'None': '#9E9E9E'      # Grey
    }
    return colors.get(severity, '#9E9E9E')


def get_threat_icon(threat_type):
    """Get icon for threat type"""
    icons = {
        'Virus': '🦠',
        'Worm': '🪱',
        'Trojan': '🐴',
        'Spyware': '👁️',
        'Adware': '📢',
        'Ransomware': '🔒',
        'Shellcode': '💻',
        'Suspicious': '❓',
        'Test Virus': '🧪'
    }
    return icons.get(threat_type, '⚠️')


def format_duration(seconds):
    """Format duration in seconds to human readable"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"


def truncate_string(s, max_length=50):
    """Truncate string to max length"""
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."


def clean_path(path):
    """Clean and normalize a path"""
    return os.path.normpath(os.path.expanduser(path))


def get_available_drives():
    """Get available drives on Windows"""
    if os.name == 'nt':
        drives = []
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
        return drives
    else:
        return ['/']


class ProgressTracker:
    """Track progress of operations"""
    
    def __init__(self, total):
        self.total = total
        self.current = 0
        self.start_time = datetime.datetime.now()
    
    def update(self, increment=1):
        """Update progress"""
        self.current += increment
    
    def get_percentage(self):
        """Get percentage complete"""
        if self.total == 0:
            return 0
        return (self.current / self.total) * 100
    
    def get_elapsed_time(self):
        """Get elapsed time"""
        return (datetime.datetime.now() - self.start_time).total_seconds()
    
    def estimate_remaining(self):
        """Estimate remaining time"""
        if self.current == 0:
            return 0
        elapsed = self.get_elapsed_time()
        rate = self.current / elapsed
        remaining = self.total - self.current
        return remaining / rate if rate > 0 else 0


# Example usage
if __name__ == "__main__":
    print("Utility Functions Test")
    print("=" * 50)
    
    # System info
    info = get_system_info()
    print(f"OS: {info['os']}")
    print(f"Python: {info['python_version']}")
    
    # Format size
    print(f"\n1 GB = {format_size(1073741824)}")
    
    # Protected locations
    print(f"\nProtected locations:")
    for loc in get_protected_locations()[:5]:
        print(f"  - {loc}")
