"""
Malware Signature Database
Contains known malware signatures for detection
"""

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

def get_signature(name):
    """Get a specific signature by name"""
    return MALWARE_SIGNATURES.get(name)

def get_all_signatures():
    """Get all malware signatures"""
    return MALWARE_SIGNATURES

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
