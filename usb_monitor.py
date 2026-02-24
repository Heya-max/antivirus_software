"""
USB Device Monitor
Monitors and auto-scans USB removable drives
"""

import os
import time
import threading
import shutil
import datetime
from scanner import MalwareScanner


class USBDevice:
    """Represents a USB removable drive"""
    def __init__(self, drive_letter, label, size, drive_type='removable'):
        self.drive_letter = drive_letter
        self.label = label
        self.size = size
        self.drive_type = drive_type
        self.mount_time = datetime.datetime.now()
        self.last_scan = None
        self.scan_results = []
    
    def get_display_name(self):
        """Get display name for the drive"""
        if self.label:
            return f"{self.label} ({self.drive_letter})"
        return self.drive_letter
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'drive_letter': self.drive_letter,
            'label': self.label,
            'size': self.size,
            'drive_type': self.drive_type,
            'mount_time': self.mount_time.isoformat(),
            'last_scan': self.last_scan.isoformat() if self.last_scan else None
        }


class USBMonitor:
    def __init__(self):
        self.scanner = MalwareScanner()
        self.monitoring = False
        self.monitor_thread = None
        self.connected_devices = {}
        self.scan_on_insert = True
        self.auto_eject_after_scan = False
        self.callback = None  # Callback for device events
        self.scan_results = {}  # Store scan results per device
    
    def get_available_drives(self):
        """Get all available drives including USB"""
        drives = []
        
        if os.name == 'nt':  # Windows
            import win32api
            import win32file
            
            # Get drive types
            drive_types = {
                2: 'removable',   # USB
                3: 'fixed',        # Hard drive
                4: 'network',      # Network drive
                5: 'cdrom',        # CD/DVD
            }
            
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                drive = f"{letter}:\\"
                try:
                    dtype = win32file.GetDriveType(drive)
                    if dtype in [2, 3]:  # Removable or fixed
                        # Check if it's accessible
                        try:
                            _, total_bytes, _ = shutil.disk_usage(drive)
                            drives.append(USBDevice(
                                drive,
                                self._get_volume_label(drive),
                                total_bytes,
                                drive_types.get(dtype, 'unknown')
                            ))
                        except Exception:
                            pass
                except Exception:
                    pass
        
        else:  # Unix-like
            # Check /media, /mnt, /Volumes for mounted removable drives
            mount_points = ['/media', '/mnt', '/Volumes']
            
            for mp in mount_points:
                if os.path.exists(mp):
                    try:
                        for item in os.listdir(mp):
                            path = os.path.join(mp, item)
                            if os.path.ismount(path) or os.path.isdir(path):
                                try:
                                    stat = os.statvfs(path)
                                    size = stat.f_blocks * stat.f_frsize
                                    drives.append(USBDevice(
                                        path,
                                        item,
                                        size,
                                        'removable'
                                    ))
                                except Exception:
                                    pass
                    except Exception:
                        pass
        
        return drives
    
    def _get_volume_label(self, drive):
        """Get volume label of a drive"""
        if os.name == 'nt':
            try:
                import win32api
                try:
                    return win32api.GetVolumeInformation(drive)[0]
                except Exception:
                    return None
            except Exception:
                return None
        return None
    
    def _get_new_drives(self):
        """Get newly connected drives compared to last check"""
        current_drives = self.get_available_drives()
        current_letters = {d.drive_letter for d in current_drives}
        previous_letters = set(self.connected_devices.keys())
        
        # Find new drives
        new_drives = []
        for drive in current_drives:
            if drive.drive_letter not in previous_letters:
                new_drives.append(drive)
        
        # Update connected devices
        self.connected_devices = {d.drive_letter: d for d in current_drives}
        
        return new_drives
    
    def _get_removed_drives(self):
        """Get drives that were removed"""
        current_drives = self.get_available_drives()
        current_letters = {d.drive_letter for d in current_drives}
        previous_letters = set(self.connected_devices.keys())
        
        # Find removed drives
        removed_letters = previous_letters - current_letters
        
        removed = []
        for letter in removed_letters:
            if letter in self.connected_devices:
                removed.append(self.connected_devices[letter])
                del self.connected_devices[letter]
        
        return removed
    
    def start_monitoring(self):
        """Start monitoring for USB device insertion"""
        if not self.monitoring:
            self.monitoring = True
            # Initialize current drives
            self.connected_devices = {d.drive_letter: d for d in self.get_available_drives()}
            self.monitor_thread = threading.Thread(target=self._run_monitor, daemon=True)
            self.monitor_thread.start()
            return {"success": True, "message": "USB monitoring started"}
        return {"success": False, "message": "Already monitoring"}
    
    def stop_monitoring(self):
        """Stop monitoring for USB devices"""
        if self.monitoring:
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=2)
            return {"success": True, "message": "USB monitoring stopped"}
        return {"success": False, "message": "Not monitoring"}
    
    def _run_monitor(self):
        """Run the monitoring loop"""
        while self.monitoring:
            try:
                # Check for new drives 
                new_drives = self._get_new_drives()
                for drive in new_drives:
                    self._on_device_inserted(drive)
                
                # Check for removed drives
                removed_drives = self._get_removed_drives()
                for drive in removed_drives:
                    self._on_device_removed(drive)
                
            except Exception as e:
                print(f"USB Monitor Error: {e}")
            
            # Check every 2 seconds
            time.sleep(2)
    
    def _on_device_inserted(self, drive):
        """Handle device insertion"""
        # Log the event
        self._log_event("DEVICE_INSERTED", f"USB device inserted: {drive.get_display_name()}")
        
        # Auto-scan if enabled
        if self.scan_on_insert:
            self.scan_device(drive)
        
        # Call callback if set
        if self.callback:
            self.callback('inserted', drive)
    
    def _on_device_removed(self, drive):
        """Handle device removal"""
        self._log_event("DEVICE_REMOVED", f"USB device removed: {drive.get_display_name()}")
        
        # Call callback if set
        if self.callback:
            self.callback('removed', drive)
    
    def _log_event(self, event_type, message):
        """Log an event"""
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"[{timestamp}] {event_type}: {message}\n"
        
        try:
            with open("usb_log.txt", 'a') as f:
                f.write(log_entry)
        except Exception:
            pass
    
    def scan_device(self, drive):
        """Scan a USB device"""
        if isinstance(drive, str):
            # Get drive object
            for d in self.get_available_drives():
                if d.drive_letter == drive or d.drive_letter == drive + '\\':
                    drive = d
                    break
            else:
                return {'success': False, 'error': 'Drive not found'}
        
        results = []
        
        try:
            # Scan the drive
            results = self.scanner.custom_scan(drive.drive_letter, fast_mode=False)
            
            # Store results
            drive.last_scan = datetime.datetime.now()
            self.scan_results[drive.drive_letter] = results
            
            # Log results
            infected = sum(1 for r in results if r.get('status') == 'Infected')
            self._log_event("SCAN_COMPLETE", 
                f"Scanned {drive.get_display_name()}: {len(results)} files, {infected} threats found")
            
            # Call callback if set
            if self.callback:
                self.callback('scan_complete', drive, results)
            
            return {
                'success': True,
                'files_scanned': len(results),
                'threats_found': infected,
                'results': results
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_connected_devices(self):
        """Get currently connected devices"""
        return list(self.connected_devices.values())
    
    def get_device_info(self, drive_letter):
        """Get information about a specific device"""
        return self.connected_devices.get(drive_letter)
    
    def get_scan_results(self, drive_letter):
        """Get scan results for a device"""
        return self.scan_results.get(drive_letter, [])
    
    def set_callback(self, callback):
        """Set callback function for device events"""
        self.callback = callback
    
    def set_auto_scan(self, enabled):
        """Enable/disable auto-scan on insert"""
        self.scan_on_insert = enabled
    
    def set_auto_eject(self, enabled):
        """Enable/disable auto-eject after scan"""
        self.auto_eject_after_scan = enabled
    
    def get_status(self):
        """Get monitoring status"""
        return {
            'monitoring': self.monitoring,
            'devices_connected': len(self.connected_devices),
            'auto_scan_enabled': self.scan_on_insert,
            'auto_eject_enabled': self.auto_eject_after_scan
        }
    
    def safe_eject(self, drive_letter):
        """Safely eject a USB device (Windows only)"""
        if os.name == 'nt':
            try:
                import win32api
                import win32file
                import pywintypes
                
                # Lock the volume
                try:
                    handle = win32file.CreateFile(
                        drive_letter,
                        win32file.GENERIC_READ,
                        win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                        None,
                        win32file.OPEN_EXISTING,
                        0,
                        None
                    )
                    win32file.DeviceIoControl(
                        handle,
                        0x00090018,  # FSCTL_LOCK_VOLUME
                        None,
                        None
                    )
                    
                    # Dismount the volume
                    win32file.DeviceIoControl(
                        handle,
                        0x0009001C,  # FSCTL_DISMOUNT_VOLUME
                        None,
                        None
                    )
                    
                    # Eject the device
                    win32file.DeviceIoControl(
                        handle,
                        0x00090028,  # IOCTL_STORAGE_EJECT_MEDIA
                        None,
                        None
                    )
                    
                    win32api.CloseHandle(handle)
                    
                    self._log_event("DEVICE_EJECTED", f"Device ejected: {drive_letter}")
                    return {'success': True, 'message': 'Device safely ejected'}
                    
                except pywintypes.error as e:
                    return {'success': False, 'error': str(e)}
                    
            except ImportError:
                return {'success': False, 'error': 'pywin32 not available'}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Only available on Windows'}


# Example usage
if __name__ == "__main__":
    usb_monitor = USBMonitor()
    
    print("USB Device Monitor")
    print("=" * 50)
    
    # Get available drives
    print("\nAvailable drives:")
    drives = usb_monitor.get_available_drives()
    for drive in drives:
        print(f"  {drive.get_display_name()} - {drive.size / (1024**3):.2f} GB")
    
    # Start monitoring
    print("\nStarting USB monitoring...")
    result = usb_monitor.start_monitoring()
    print(f"Status: {result}")
    
    # Get status
    status = usb_monitor.get_status()
    print(f"Monitoring: {status['monitoring']}")
    print(f"Devices: {status['devices_connected']}")
    
    # Stop monitoring
    print("\nStopping monitoring...")
    usb_monitor.stop_monitoring()
    print("Done")
