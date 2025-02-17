# ThreatFinder - Lightweight Threat Detection Tool

**ThreatFinder** is a cross-platform Python-based threat detection tool designed to identify malicious files, suspicious processes, and unusual network connections. It supports Windows and Linux operating systems and provides options for both targeted and full system scans.

---

## Features
- **Process Scanning:** Identifies processes with high CPU/memory usage or suspicious behavior.
- **Network Connection Scanning:** Lists all active network connections and flags anomalies.
- **File Scanning:** Scans files for known malware hashes using an up-to-date database.
- **Full System Scan:** Performs a comprehensive scan of processes, network connections, and all files in the system.
- **Cross-Platform Support:** Works seamlessly on both Windows and Linux.
- **Malware Database Integration:** Fetches the latest malware hashes from the Malshare API.

---

## Installation
**Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/threatfinder.git
   cd threatfinder
   pip install -r requirements.txt
   python threatfinder.py
```
