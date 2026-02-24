"""
Malware Signature Database
Contains known malware signatures for detection
"""

import os
import json
import datetime
import urllib.request

# Version info
DATABASE_VERSION = "1.0.0"
DATABASE_URL = "https://example.com/antivirus/signatures.json"
LAST_UPDATE = None

# Known malware signatures (hex patterns commonly found in malware)
MALWARE_SIGNATURES = {
    # Virus signatures
    "EICAR_TEST": {
        "pattern": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        "type": "Test Virus",
        "severity": "Low"
    },
    "EICAR_COM": {
        "pattern": b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
        "type": "Test Virus",
        "severity": "Low"
    },
    
    # Common virus patterns
    "PE_HEADER_MALICIOUS": {
        "pattern": b"MZ\x90\x00\x03\x00\x00\x00",
        "type": "Virus",
        "severity": "High"
    },
    
    # Worm patterns
    "NETWORK_WORM_1": {
        "pattern": b"\xeb\x12\x90\x90\x90\x90\x90\x90",
        "type": "Worm",
        "severity": "High"
    },
    
    # Trojan patterns
    "TROJAN_BACKDOOR": {
        "pattern": b"BACKDOOR",
        "type": "Trojan",
        "severity": "Critical"
    },
    "TROJAN_RAT": {
        "pattern": b"RemoteAdministration",
        "type": "Trojan",
        "severity": "Critical"
    },
    "TROJAN_KEYLOGGER": {
        "pattern": b"KeyLogger",
        "type": "Trojan",
        "severity": "Critical"
    },
    
    # Spyware patterns
    "SPYWARE_TRACKER": {
        "pattern": b"UserActivityMonitor",
        "type": "Spyware",
        "severity": "High"
    },
    "SPYWARE_COOKIE": {
        "pattern": b"tracking cookie",
        "type": "Spyware",
        "severity": "Low"
    },
    
    # Adware patterns
    "ADWARE_POPUP": {
        "pattern": b"popup advertiser",
        "type": "Adware",
        "severity": "Medium"
    },
    "ADWARE_BROWSER": {
        "pattern": b"BHO.dll",
        "type": "Adware",
        "severity": "Medium"
    },
    
    # Ransomware patterns
    "RANSOMWARE_ENCRYPTION": {
        "pattern": b"encrypted",
        "type": "Ransomware",
        "severity": "Critical"
    },
    "RANSOMWARE_NOTE": {
        "pattern": b"ransom",
        "type": "Ransomware",
        "severity": "Critical"
    },
    "RANSOMWARE_EXTENSION": {
        "pattern": b".encrypted",
        "type": "Ransomware",
        "severity": "Critical"
    },
    
    # Generic malicious patterns
    "SHELLCODE": {
        "pattern": b"\x90\x90\x90\x90\x90\x90\x90\x90",
        "type": "Shellcode",
        "severity": "High"
    },
    "SUSPICIOUS_API": {
        "pattern": b"VirtualAlloc",
        "type": "Suspicious",
        "severity": "Medium"
    },
    "PASSWORD_STEALER": {
        "pattern": b"GetPassword",
        "type": "Spyware",
        "severity": "Critical"
    }
}

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".com", ".pif", ".scr",
    ".vbs", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".vba",
    ".vrox", ".docm", ".xlsm", ".pptm", ".jar", ".bat",
    ".reg", ".ini", ".inf", ".sys", ".ocx", ".rootkit"
]

# Known malicious file names
MALICIOUS_FILENAMES = [
    "autorun.inf", "desktop.ini", "thumbs.db",
    "setup.exe", "update.exe", "install.exe",
    "crack.exe", "keygen.exe", "patch.exe",
    "free_software.exe", "movie.exe", "music.exe",
    "invoice.exe", "document.exe", "photo.exe"
]

# Suspicious behaviors
SUSPICIOUS_BEHAVIORS = [
    "modifying system files",
    "disabling antivirus",
    "creating hidden files",
    "modifying registry",
    "network communication",
    "keylogging",
    "screen capture",
    "file encryption",
    "mass file deletion",
    "privilege escalation"
]

# Additional threat categories
THREAT_CATEGORIES = {
    "Virus": "Malware that replicates itself",
    "Worm": "Self-replicating malware that spreads across networks",
    "Trojan": "Malware disguised as legitimate software",
    "Spyware": "Software that monitors user activity",
    "Adware": "Advertising-supported software",
    "Ransomware": "Encrypts files and demands payment",
    "Rootkit": "Hides malicious software from detection",
    "Keylogger": "Records keystrokes to steal information",
    "Botnet": "Network of compromised computers",
    "Backdoor": "Hidden access to a system"
}

def get_signature(name):
    """Get a specific signature by name"""
    return MALWARE_SIGNATURES.get(name)

def get_all_signatures():
    """Get all malware signatures"""
    return MALWARE_SIGNATURES

def get_signature_count():
    """Get total number of signatures"""
    return len(MALWARE_SIGNATURES)

def get_severity_level(severity):
    """Get numeric severity level"""
    levels = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }
    return levels.get(severity, 0)

def check_extension(filename):
    """Check if file extension is suspicious"""
    import os
    ext = os.path.splitext(filename)[1].lower()
    return ext in SUSPICIOUS_EXTENSIONS

def check_filename(filename):
    """Check if filename is known malicious"""
    import os
    name = os.path.basename(filename).lower()
    return name in MALICIOUS_FILENAMES

def add_signature(name, pattern, threat_type, severity):
    """Add a new malware signature"""
    global MALWARE_SIGNATURES
    
    if isinstance(pattern, str):
        pattern = pattern.encode('utf-8')
    
    MALWARE_SIGNATURES[name] = {
        'pattern': pattern,
        'type': threat_type,
        'severity': severity,
        'added_date': datetime.datetime.now().isoformat(),
        'custom': True
    }
    return True

def remove_signature(name):
    """Remove a malware signature"""
    global MALWARE_SIGNATURES
    
    if name in MALWARE_SIGNATURES:
        del MALWARE_SIGNATURES[name]
        return True
    return False

def get_database_info():
    """Get database information"""
    global LAST_UPDATE, DATABASE_VERSION
    
    return {
        'version': DATABASE_VERSION,
        'signature_count': len(MALWARE_SIGNATURES),
        'last_update': LAST_UPDATE,
        'suspicious_extensions': len(SUSPICIOUS_EXTENSIONS),
        'malicious_filenames': len(MALICIOUS_FILENAMES),
        'threat_categories': len(THREAT_CATEGORIES)
    }

def update_definitions(force=False):
    """Update virus definitions from remote source"""
    global LAST_UPDATE, DATABASE_VERSION, MALWARE_SIGNATURES
    
    if not force and LAST_UPDATE:
        try:
            last = datetime.datetime.fromisoformat(LAST_UPDATE)
            if (datetime.datetime.now() - last).days < 1:
                return {
                    'success': False,
                    'message': 'Definitions were updated recently. Use force=True to update anyway.',
                    'last_update': LAST_UPDATE
                }
        except Exception:
            pass
    
    try:
        try:
            response = urllib.request.urlopen(DATABASE_URL, timeout=10)
            data = json.loads(response.read().decode('utf-8'))
            
            new_signatures = data.get('signatures', {})
            for name, sig in new_signatures.items():
                if name not in MALWARE_SIGNATURES:
                    MALWARE_SIGNATURES[name] = sig
            
            DATABASE_VERSION = data.get('version', DATABASE_VERSION)
        except Exception:
            pass
        
        LAST_UPDATE = datetime.datetime.now().isoformat()
        save_definitions()
        
        return {
            'success': True,
            'message': f'Definitions updated. Total signatures: {len(MALWARE_SIGNATURES)}',
            'last_update': LAST_UPDATE,
            'version': DATABASE_VERSION
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Update failed: {str(e)}',
            'last_update': LAST_UPDATE
        }

def save_definitions():
    """Save definitions to local file"""
    try:
        data = {
            'version': DATABASE_VERSION,
            'last_update': LAST_UPDATE,
            'signatures': MALWARE_SIGNATURES,
            'suspicious_extensions': SUSPICIOUS_EXTENSIONS,
            'malicious_filenames': MALICIOUS_FILENAMES
        }
        
        with open('signature_database.json', 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving definitions: {e}")
        return False

def load_definitions():
    """Load definitions from local file"""
    global LAST_UPDATE, DATABASE_VERSION, MALWARE_SIGNATURES
    
    try:
        if os.path.exists('signature_database.json'):
            with open('signature_database.json', 'r') as f:
                data = json.load(f)
            
            DATABASE_VERSION = data.get('version', DATABASE_VERSION)
            LAST_UPDATE = data.get('last_update')
            
            signatures = data.get('signatures', {})
            for name, sig in signatures.items():
                MALWARE_SIGNATURES[name] = sig
            
            return True
    except Exception as e:
        print(f"Error loading definitions: {e}")
    return False

def reset_to_defaults():
    """Reset to default signatures"""
    global MALWARE_SIGNATURES
    
    MALWARE_SIGNATURES = {
        name: sig for name, sig in MALWARE_SIGNATURES.items()
        if not sig.get('custom', False)
    }
    save_definitions()
    return True

# Initialize
load_definitions()
