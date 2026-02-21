"""
Malware Scanner Engine
Scans files for malware signatures and suspicious behavior
Optimized for faster full scans
"""

import os
import hashlib
import datetime
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import signature_db as sig_db


class ScanCache:
    """Cache for storing clean file hashes to skip unchanged files"""
    
    def __init__(self, cache_file="scan_cache.json"):
        self.cache_file = cache_file
        self.cache = self._load_cache()
        self.lock = threading.Lock()
    
    def _load_cache(self):
        """Load cache from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _save_cache(self):
        """Save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception:
            pass
    
    def is_clean(self, filepath, mtime, size):
        """Check if file is in cache and unchanged"""
        with self.lock:
            key = filepath
            if key in self.cache:
                entry = self.cache[key]
                if entry['mtime'] == mtime and entry['size'] == size:
                    return True
            return False
    
    def add_clean_file(self, filepath, file_hash, mtime, size):
        """Add clean file to cache"""
        with self.lock:
            self.cache[filepath] = {
                'hash': file_hash,
                'mtime': mtime,
                'size': size,
                'timestamp': datetime.datetime.now().isoformat()
            }
            # Save periodically (every 100 entries)
            if len(self.cache) % 100 == 0:
                self._save_cache()
    
    def save(self):
        """Save cache to file"""
        self._save_cache()
    
    def clear(self):
        """Clear the cache"""
        with self.lock:
            self.cache = {}
            self._save_cache()


# Safe file extensions that can be skipped in fast mode
SAFE_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp', '.tiff',
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a',
    '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm',
    '.pdf', '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    '.html', '.htm', '.css', '.xml', '.json'
}

# High-risk extensions that should always be scanned
RISK_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.bat', '.cmd', '.com', '.pif', '.scr',
    '.vbs', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.vba', '.vrox',
    '.docm', '.xlsm', '.pptm', '.jar', '.reg', '.inf', '.ocx', '.rootkit',
    '.msi', '.hta', '.cab', '.msp', '.gadget', '.application'
}


class MalwareScanner:
    def __init__(self):
        self.scanned_files = 0
        self.threats_found = 0
        self.scan_results = []
        self.quarantined_files = []
        self.lock = threading.Lock()
        self.scan_cache = ScanCache()
        self.fast_mode = True  # Enable fast scanning by default
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(8192), b""):  # Increased buffer size
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return None
    
    def _should_skip_file(self, filepath):
        """Check if file should be skipped in fast mode"""
        if not self.fast_mode:
            return False
        
        ext = os.path.splitext(filepath)[1].lower()
        
        # Always scan risky extensions
        if ext in RISK_EXTENSIONS:
            return False
        
        # Skip safe extensions in fast mode
        if ext in SAFE_EXTENSIONS:
            return True
        
        # For unknown extensions, still scan but with lower priority
        # This is a balance between speed and security
        return False
    
    def scan_file(self, filepath, check_cache=True):
        """Scan a single file for malware with optimizations"""
        result = {
            'file': filepath,
            'threats': [],
            'severity': 'None',
            'status': 'Clean',
            'hash': None,
            'size': 0,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            # Get file info
            if os.path.exists(filepath):
                file_stat = os.stat(filepath)
                result['size'] = file_stat.st_size
                
                # Check cache first (skip unchanged clean files)
                if check_cache and self.scan_cache.is_clean(filepath, file_stat.st_mtime, file_stat.st_size):
                    # Update counters but skip actual scanning
                    with self.lock:
                        self.scanned_files += 1
                    result['cached'] = True
                    return result

                # Fast mode: skip safe file types
                if self._should_skip_file(filepath):
                    with self.lock:
                        self.scanned_files += 1
                    return result

                # Quick checks first (fast)
                if sig_db.check_extension(filepath):
                    result['threats'].append({
                        'type': 'Suspicious Extension',
                        'severity': 'Medium',
                        'description': f"Suspicious file extension: {os.path.splitext(filepath)[1]}"
                    })

                if sig_db.check_filename(filepath):
                    result['threats'].append({
                        'type': 'Known Malicious File',
                        'severity': 'High',
                        'description': 'Filename matches known malicious files'
                    })

                # Read a small portion of the file for signature matching (stream-friendly)
                # Optimize: Read larger chunks for better I/O performance
                try:
                    with open(filepath, 'rb') as f:
                        # Read first 128KB for better detection (increased from 64KB)
                        content = f.read(131072)

                        # Optimize: Use more efficient pattern matching
                        # Group critical signatures first for early detection
                        critical_signatures = [
                            (sig_name, sig_info) for sig_name, sig_info 
                            in sig_db.MALWARE_SIGNATURES.items()
                            if sig_info.get('severity') in ['Critical', 'High']
                        ]
                        
                        # Check critical signatures first
                        for sig_name, sig_info in critical_signatures:
                            pattern = sig_info['pattern']
                            if isinstance(pattern, str):
                                pattern = pattern.encode('utf-8')

                            if pattern in content:
                                result['threats'].append({
                                    'type': sig_info['type'],
                                    'severity': sig_info['severity'],
                                    'signature': sig_name,
                                    'description': f"Found {sig_info['type']} pattern"
                                })
                                # Early exit for critical threats
                                if sig_info['severity'] == 'Critical':
                                    # Compute hash for critical threats
                                    result['hash'] = self.calculate_file_hash(filepath)
                                    
                                    # Determine severity
                                    result['status'] = 'Infected'
                                    result['severity'] = 'Critical'
                                    
                                    # Update counters
                                    with self.lock:
                                        self.scanned_files += 1
                                        self.threats_found += 1
                                    
                                    return result
                    
                    # If no critical threats found, check remaining signatures
                    for sig_name, sig_info in sig_db.MALWARE_SIGNATURES.items():
                        if sig_info.get('severity') in ['Critical', 'High']:
                            continue  # Already checked
                            
                        pattern = sig_info['pattern']
                        if isinstance(pattern, str):
                            pattern = pattern.encode('utf-8')

                        if pattern in content:
                            result['threats'].append({
                                'type': sig_info['type'],
                                'severity': sig_info['severity'],
                                'signature': sig_name,
                                'description': f"Found {sig_info['type']} pattern"
                            })
                            # Early exit for high severity if in fast mode
                            if self.fast_mode and sig_info['severity'] == 'High':
                                break
                                        
                except Exception:
                    pass  # Skip files that can't be read

                # If threats detected, compute full file hash (expensive) lazily
                if result['threats']:
                    result['hash'] = self.calculate_file_hash(filepath)
                else:
                    # Cache clean files for faster subsequent scans
                    file_hash = self.calculate_file_hash(filepath)
                    self.scan_cache.add_clean_file(filepath, file_hash, file_stat.st_mtime, file_stat.st_size)

                # Determine overall status and severity
                if result['threats']:
                    result['status'] = 'Infected'
                    max_severity = 0
                    for threat in result['threats']:
                        sev = sig_db.get_severity_level(threat['severity'])
                        if sev > max_severity:
                            max_severity = sev

                    severity_map = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
                    result['severity'] = severity_map.get(max_severity, 'Unknown')

                # Update counters in a thread-safe manner
                with self.lock:
                    self.scanned_files += 1
                    if result['status'] == 'Infected':
                        self.threats_found += 1
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def scan_directory(self, directory, extensions=None, recursive=True, check_cache=True):
        """Scan all files in a directory with optimized parallel processing"""
        results = []

        try:
            # Collect files to scan
            entries = []
            if recursive:
                for root, dirs, files in os.walk(directory):
                    # Skip system directories for faster scanning
                    dirs[:] = [d for d in dirs if d not in ['$RECYCLE.BIN', 'System Volume Information', '.git']]
                    for filename in files:
                        if extensions and not any(filename.endswith(ext) for ext in extensions):
                            continue
                        filepath = os.path.join(root, filename)
                        entries.append(filepath)
            else:
                with os.scandir(directory) as it:
                    for entry in it:
                        if not entry.is_file():
                            continue
                        if extensions and not any(entry.name.endswith(ext) for ext in extensions):
                            continue
                        entries.append(entry.path)

            if not entries:
                return results

            # Use a ThreadPoolExecutor for I/O-bound parallel scanning
            # Increased workers for better parallelism
            workers = min(64, (os.cpu_count() or 4) * 8)  # Increased from 32
            with ThreadPoolExecutor(max_workers=workers) as ex:
                future_to_path = {
                    ex.submit(self.scan_file, p, check_cache): p 
                    for p in entries
                }
                for fut in as_completed(future_to_path):
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = {'file': future_to_path.get(fut), 'error': str(e)}
                    results.append(res)
                    self.scan_results.append(res)

        except Exception as e:
            results.append({'error': str(e)})

        return results
    
    def quick_scan(self):
        """Perform a quick scan of common malware locations"""
        results = []
        quick_scan_paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            os.path.join(os.environ.get('TEMP', '')),
            "C:/Windows/Temp" if os.name == 'nt' else '/tmp'
        ]
        
        for path in quick_scan_paths:
            if os.path.exists(path):
                result = self.scan_directory(path, recursive=False)
                results.extend(result)
        
        return results
    
    def full_scan(self, drive="C:/", fast_mode=True):
        """Perform a full system scan with optimized performance"""
        results = []
        self.fast_mode = fast_mode  # Enable/disable fast mode
        
        # Scan common locations - prioritized by risk
        scan_paths = [
            drive,
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Music"),
            os.path.expanduser("~/Videos"),
        ]

        # Filter existing paths
        paths = [p for p in scan_paths if p and os.path.exists(p)]
        if not paths:
            return results

        # Parallelize scanning across top-level paths to speed up full scans.
        # Increased workers for better parallelism
        path_workers = min(8, len(paths))  # Increased from 4
        try:
            with ThreadPoolExecutor(max_workers=path_workers) as ex:
                # Pass fast_mode and check_cache to scan_directory
                future_to_path = {
                    ex.submit(self.scan_directory, p, None, True, True): p 
                    for p in paths
                }
                for fut in as_completed(future_to_path):
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = [{'error': str(e)}]
                    results.extend(res)
        except Exception:
            # Fallback: scan sequentially
            for path in paths:
                try:
                    res = self.scan_directory(path, recursive=True)
                    results.extend(res)
                except Exception:
                    pass
        
        # Save cache after full scan completes
        self.scan_cache.save()
        
        return results
    
    def custom_scan(self, path, fast_mode=False):
        """Scan a custom path"""
        results = []
        self.fast_mode = fast_mode
        
        if os.path.exists(path):
            if os.path.isfile(path):
                result = self.scan_file(path, check_cache=False)
                results.append(result)
            elif os.path.isdir(path):
                result = self.scan_directory(path, recursive=True, check_cache=False)
                results.extend(result)
        
        return results
    
    def get_scan_summary(self):
        """Get summary of the last scan"""
        clean = sum(1 for r in self.scan_results if r['status'] == 'Clean')
        infected = sum(1 for r in self.scan_results if r['status'] == 'Infected')
        cached = sum(1 for r in self.scan_results if r.get('cached', False))
        
        return {
            'total_files': self.scanned_files,
            'clean_files': clean,
            'infected_files': infected,
            'threats_detected': self.threats_found,
            'cached_files': cached
        }
    
    def reset_stats(self):
        """Reset scan statistics"""
        self.scanned_files = 0
        self.threats_found = 0
        self.scan_results = []
    
    def clear_cache(self):
        """Clear the scan cache"""
        self.scan_cache.clear()
    
    def set_fast_mode(self, enabled):
        """Enable or disable fast mode scanning"""
        self.fast_mode = enabled


# Example usage
if __name__ == "__main__":
    scanner = MalwareScanner()
    
    # Test scanning
    print("Antivirus Scanner Engine")
    print("=" * 50)
    
    # Quick scan
    print("\nPerforming quick scan...")
    results = scanner.quick_scan()
    
    print(f"Files scanned: {len(results)}")
    infected = sum(1 for r in results if r['status'] == 'Infected')
    print(f"Threats found: {infected}")
