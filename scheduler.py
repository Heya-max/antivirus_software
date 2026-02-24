"""
Scheduled Scan Manager
Manages scheduled automatic scans (daily, weekly, monthly)
"""

import os
import json
import datetime
import threading
import time
from scanner import MalwareScanner


class ScheduledScan:
    """Represents a scheduled scan"""
    def __init__(self, scan_type, frequency, time_str, enabled=True, path="C:/"):
        self.scan_type = scan_type  # 'quick', 'full', 'custom'
        self.frequency = frequency  # 'daily', 'weekly', 'monthly'
        self.time_str = time_str  # HH:MM format
        self.enabled = enabled
        self.path = path
        self.last_run = None
        self.next_run = self._calculate_next_run()
    
    def _calculate_next_run(self):
        """Calculate next run time based on frequency"""
        now = datetime.datetime.now()
        hour, minute = map(int, self.time_str.split(':'))
        
        if self.frequency == 'daily':
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += datetime.timedelta(days=1)
        
        elif self.frequency == 'weekly':
            # Default to Sunday
            days_ahead = 6 - now.weekday()
            if days_ahead < 0:
                days_ahead += 7
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            next_run += datetime.timedelta(days=days_ahead)
            if next_run <= now:
                next_run += datetime.timedelta(weeks=1)
        
        elif self.frequency == 'monthly':
            # Default to 1st of next month
            if now.month == 12:
                next_run = datetime.datetime(now.year + 1, 1, 1, hour, minute)
            else:
                next_run = datetime.datetime(now.year, now.month + 1, 1, hour, minute)
            if next_run <= now:
                if now.month == 12:
                    next_run = datetime.datetime(now.year + 1, 1, 1, hour, minute)
                else:
                    next_run = datetime.datetime(now.year, now.month + 1, 1, hour, minute)
        
        return next_run
    
    def should_run(self):
        """Check if the scan should run now"""
        if not self.enabled:
            return False
        return datetime.datetime.now() >= self.next_run
    
    def update_next_run(self):
        """Update next run time after execution"""
        self.last_run = datetime.datetime.now()
        self.next_run = self._calculate_next_run()
    
    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'scan_type': self.scan_type,
            'frequency': self.frequency,
            'time_str': self.time_str,
            'enabled': self.enabled,
            'path': self.path,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'next_run': self.next_run.isoformat() if self.next_run else None
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create from dictionary"""
        scan = cls(
            data['scan_type'],
            data['frequency'],
            data['time_str'],
            data.get('enabled', True),
            data.get('path', 'C:/')
        )
        if data.get('last_run'):
            scan.last_run = datetime.datetime.fromisoformat(data['last_run'])
        if data.get('next_run'):
            scan.next_run = datetime.datetime.fromisoformat(data['next_run'])
        return scan


class ScanScheduler:
    def __init__(self, config_file="scheduled_scans.json"):
        self.config_file = config_file
        self.scheduled_scans = []
        self.scheduler_thread = None
        self.running = False
        self.scanner = MalwareScanner()
        self.callback = None  # Callback function for UI updates
        self.load_schedules()
    
    def load_schedules(self):
        """Load scheduled scans from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.scheduled_scans = [ScheduledScan.from_dict(s) for s in data]
            except Exception:
                self.scheduled_scans = []
    
    def save_schedules(self):
        """Save scheduled scans to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump([s.to_dict() for s in self.scheduled_scans], f, indent=4)
        except Exception as e:
            print(f"Error saving schedules: {e}")
    
    def add_schedule(self, scan_type, frequency, time_str, path="C:/"):
        """Add a new scheduled scan"""
        scan = ScheduledScan(scan_type, frequency, time_str, True, path)
        self.scheduled_scans.append(scan)
        self.save_schedules()
        return scan
    
    def remove_schedule(self, index):
        """Remove a scheduled scan"""
        if 0 <= index < len(self.scheduled_scans):
            self.scheduled_scans.pop(index)
            self.save_schedules()
            return True
        return False
    
    def toggle_schedule(self, index):
        """Toggle a scheduled scan enabled/disabled"""
        if 0 <= index < len(self.scheduled_scans):
            self.scheduled_scans[index].enabled = not self.scheduled_scans[index].enabled
            self.scheduled_scans[index].next_run = self.scheduled_scans[index]._calculate_next_run()
            self.save_schedules()
            return True
        return False
    
    def get_schedules(self):
        """Get all scheduled scans"""
        return self.scheduled_scans
    
    def get_next_scan_time(self):
        """Get the next scheduled scan time"""
        enabled_scans = [s for s in self.scheduled_scans if s.enabled]
        if not enabled_scans:
            return None
        return min(s.next_run for s in enabled_scans)
    
    def set_callback(self, callback):
        """Set callback function for scan completion"""
        self.callback = callback
    
    def start(self):
        """Start the scheduler"""
        if not self.running:
            self.running = True
            self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
            self.scheduler_thread.start()
            return {"success": True, "message": "Scheduler started"}
        return {"success": False, "message": "Scheduler already running"}
    
    def stop(self):
        """Stop the scheduler"""
        if self.running:
            self.running = False
            if self.scheduler_thread:
                self.scheduler_thread.join(timeout=2)
            return {"success": True, "message": "Scheduler stopped"}
        return {"success": False, "message": "Scheduler not running"}
    
    def _run_scheduler(self):
        """Run the scheduler loop"""
        while self.running:
            for scan in self.scheduled_scans:
                if scan.should_run():
                    # Run the scan
                    results = self._execute_scan(scan)
                    
                    # Update next run time
                    scan.update_next_run()
                    self.save_schedules()
                    
                    # Call callback if set
                    if self.callback:
                        self.callback(scan, results)
            
            # Check every minute
            time.sleep(60)
    
    def _execute_scan(self, scan):
        """Execute a scheduled scan"""
        results = []
        
        if scan.scan_type == 'quick':
            results = self.scanner.quick_scan()
        elif scan.scan_type == 'full':
            results = self.scanner.full_scan(scan.path)
        elif scan.scan_type == 'custom':
            results = self.scanner.custom_scan(scan.path)
        
        return results
    
    def run_now(self, index):
        """Manually run a scheduled scan"""
        if 0 <= index < len(self.scheduled_scans):
            scan = self.scheduled_scans[index]
            results = self._execute_scan(scan)
            scan.update_next_run()
            self.save_schedules()
            return results
        return []


# Example usage
if __name__ == "__main__":
    scheduler = ScanScheduler()
    
    # Add some scheduled scans
    scheduler.add_schedule('quick', 'daily', '09:00')
    scheduler.add_schedule('full', 'weekly', '02:00', 'C:/')
    
    print("Scan Scheduler")
    print("=" * 50)
    
    # Start scheduler
    print("Starting scheduler...")
    result = scheduler.start()
    print(f"Status: {result}")
    
    # Get schedules
    schedules = scheduler.get_schedules()
    print(f"\nScheduled scans: {len(schedules)}")
    for i, s in enumerate(schedules):
        print(f"  {i+1}. {s.scan_type.upper()} - {s.frequency} at {s.time_str}")
        print(f"     Next run: {s.next_run}")
    
    # Stop scheduler
    print("\nStopping scheduler...")
    scheduler.stop()
    print("Done")
