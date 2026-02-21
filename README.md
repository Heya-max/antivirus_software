# Guardian Antivirus

A comprehensive antivirus application with real-time protection, malware detection, file scanning, and quarantine management. Built with CustomTkinter for a modern UI with dark/light themes.

## Features

- **Detection**: Scans files, programs, and incoming data for known malware signatures and suspicious behavior
- **Prevention**: Blocks unsafe websites, downloads, or attachments
- **Removal**: Quarantines or deletes malicious software
- **Real-time protection**: Continuously monitors your system in the background
- **System scanning**: Manual or scheduled scans (Full, Quick, Custom)
- **Modern UI**: Beautiful dark/light themes with CustomTkinter

## Types of Threats It Protects Against

- 🦠 Viruses – malicious code that spreads by infecting files
- 🪱 Worms – self-replicating programs that spread across networks
- 🐴 Trojans – disguised as legitimate software but harmful once installed
- 👁️ Spyware & Adware – secretly track your activity or bombard you with ads
- 🔒 Ransomware – locks your files and demands payment to restore access

## Requirements

- Python 3.x
- customtkinter (for modern UI)
- psutil (for system monitoring)
- tkinter (included with Python)

## Installation

```
bash
pip install customtkinter psutil
```

## Usage

Run the antivirus:
```
bash
python main.py
```

## Project Structure

- `main.py` - Main application entry point and GUI (CustomTkinter)
- `scanner.py` - Malware scanning engine
- `signature_db.py` - Malware signature database
- `quarantine.py` - Quarantine management
- `real_time_monitor.py` - Real-time protection system
- `utils.py` - Utility functions

## Scan Types

- ⚡ **Quick Scan** – Checks common infection areas (Downloads, Documents, Temp folders)
- 🔎 **Full Scan** – Scans entire system for malware
- 📁 **Custom Scan** – Scan a selected folder of your choice

## Detection Methods

1. **Signature-Based Detection** – Compares files against a database of known malware patterns
2. **Heuristic Detection** – Looks for suspicious behavior and file patterns
3. **Entropy Detection** – Identifies encrypted files that may indicate ransomware

## Dark/Light Themes

Toggle between dark and light modes using the theme switch in the sidebar for a personalized experience!
