import os
import psutil
import hashlib
import datetime
import requests  # For fetching malware hashes from external sources
import pefile  # For analyzing PE files
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # For disassembly

# File containing known malware hashes
MALWARE_HASHES_FILE = "malwarehashes.txt"
SUSPICIOUS_CPU_THRESHOLD = 80.0  # CPU usage percentage
SUSPICIOUS_MEMORY_THRESHOLD = 100 * 1024 * 1024  # Memory usage in bytes (100 MB)
MAX_HASH_COUNT = 10000  # Maximum number of hashes to keep

MALSHARE_API_KEY = "a8e72bc66ce15f320a283783f16763d8b51d337c3ff36c223553f41d684eb8a0"
MALSHARE_API_URL = "https://malshare.com/api.php"

def fetch_latest_hashes():
    """Fetch the latest malware hashes from the Malshare API."""
    print("[+] Fetching latest malware hashes from Malshare...")
    try:
        # Make an API request to fetch the latest malware hashes
        response = requests.get(MALSHARE_API_URL, params={"api_key": MALSHARE_API_KEY, "action": "getlist"})
        if response.status_code == 200:
            latest_hashes = response.text.splitlines()
            latest_hashes = remove_duplicates(latest_hashes)

            # Load existing hashes and combine with the new ones
            if os.path.exists(MALWARE_HASHES_FILE):
                with open(MALWARE_HASHES_FILE, "r") as f:
                    existing_hashes = [line.strip() for line in f if line.strip()]
                combined_hashes = remove_duplicates(latest_hashes + existing_hashes)
            else:
                combined_hashes = latest_hashes

            # Limit to the most recent hashes
            combined_hashes = combined_hashes[:MAX_HASH_COUNT]

            with open(MALWARE_HASHES_FILE, "w") as f:
                f.write("\n".join(combined_hashes))

            print(f"[+] Updated {MALWARE_HASHES_FILE} with {len(combined_hashes)} unique hashes.")
        else:
            print(f"[!] Failed to fetch hashes: HTTP {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"[!] Error fetching hashes: {e}")

def load_known_hashes():
    """Load known malware hashes from a file."""
    if not os.path.exists(MALWARE_HASHES_FILE):
        print(f"[!] Malware hashes file '{MALWARE_HASHES_FILE}' not found.")
        return set()
    with open(MALWARE_HASHES_FILE, "r") as f:
        return set(remove_duplicates([line.strip() for line in f if line.strip()]))

def remove_duplicates(hash_list):
    """Remove duplicate hashes from a list."""
    return list(set(hash_list))

def log_report(logs):
    """Log the findings to a file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"threatfinder_report_{timestamp}.log"
    with open(log_file, "w") as f:
        f.write("\n".join(logs))
    print(f"[+] Report saved to {log_file}")

def scan_processes():
    """Scan running processes for anomalies."""
    logs = ["[Process Scan Report]"]
    suspicious_files = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'memory_info', 'cpu_percent', 'exe']):
        try:
            proc_info = proc.info
            if proc_info['cpu_percent'] > SUSPICIOUS_CPU_THRESHOLD or (proc_info['memory_info'] and proc_info['memory_info'].rss > SUSPICIOUS_MEMORY_THRESHOLD):
                logs.append(f"[SUSPICIOUS PROCESS] PID: {proc_info['pid']}, Name: {proc_info['name']}, CPU: {proc_info['cpu_percent']}%, Memory: {proc_info['memory_info'].rss} bytes")
                if proc_info['exe']:
                    suspicious_files.append(proc_info['exe'])
            else:
                logs.append(f"PID: {proc_info['pid']}, Name: {proc_info['name']}, User: {proc_info['username']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return logs, suspicious_files

def scan_network_connections():
    """Scan network connections for anomalies."""
    logs = ["[Network Scan Report]"]
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
        logs.append(f"Local Address: {laddr}, Remote Address: {raddr}, Status: {conn.status}")
    return logs

def scan_files(directory, known_hashes):
    """Scan files in a directory for known malware signatures."""
    logs = ["[File Scan Report]"]
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "rb") as f:
                    file_hash = hashlib.md5(f.read()).hexdigest()
                if file_hash in known_hashes:
                    logs.append(f"[MALWARE DETECTED] File: {file_path}, MD5: {file_hash}")
            except (PermissionError, FileNotFoundError):
                continue
    return logs

def analyze_suspicious_files(suspicious_files, known_hashes):
    """Analyze suspicious files to check if they match known malware hashes or contain malicious code."""
    logs = ["[Suspicious File Analysis]"]
    for file_path in suspicious_files:
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            if file_hash in known_hashes:
                logs.append(f"[MALWARE DETECTED] File: {file_path}, MD5: {file_hash}")
            else:
                logs.append(f"[FALSE POSITIVE] File: {file_path}, MD5: {file_hash}")

            # Analyze PE files
            if file_path.endswith(".exe"):
                logs.extend(analyze_pe_file(file_path))

        except (PermissionError, FileNotFoundError):
            logs.append(f"[ERROR] Could not analyze file: {file_path}")
    return logs

def analyze_pe_file(file_path):
    """Analyze a PE file for suspicious imports or sections."""
    logs = [f"[PE File Analysis] File: {file_path}"]
    try:
        pe = pefile.PE(file_path)

        # Check for suspicious imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for func in entry.imports:
                    if func.name and b"evil" in func.name.lower():  # Example pattern
                        logs.append(f"[SUSPICIOUS IMPORT] {func.name.decode()}")

        # Disassemble .text section
        if hasattr(pe, 'sections'):
            for section in pe.sections:
                if b".text" in section.Name:
                    disasm_logs = disassemble_section(section.get_data())
                    logs.extend(disasm_logs)

    except Exception as e:
        logs.append(f"[ERROR] Failed to analyze PE file: {e}")
    return logs

def disassemble_section(section_data):
    """Disassemble binary code from a section."""
    logs = ["[Disassembly]"]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    try:
        for instruction in md.disasm(section_data, 0x1000):
            logs.append(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")
    except Exception as e:
        logs.append(f"[ERROR] Disassembly failed: {e}")
    return logs

def main():
    fetch_latest_hashes()  # Fetch the latest hashes before scanning

    known_hashes = load_known_hashes()
    if not known_hashes:
        print("[!] No known malware hashes loaded. Aborting scans.")
        return

    print("ThreatFinder - Lightweight Threat Detection Tool")
    print("1. Scan Processes")
    print("2. Scan Network Connections")
    print("3. Scan Files in Directory")
    print("4. Perform All Scans")
    choice = input("Enter your choice: ")

    all_logs = []

    if choice == "1":
        process_logs, suspicious_files = scan_processes()
        all_logs.extend(process_logs)
        if suspicious_files:
            all_logs.extend(analyze_suspicious_files(suspicious_files, known_hashes))
    elif choice == "2":
        all_logs.extend(scan_network_connections())
    elif choice == "3":
        directory = input("Enter directory to scan: ")
        if os.path.isdir(directory):
            all_logs.extend(scan_files(directory, known_hashes))
        else:
            print("[!] Invalid directory")
    elif choice == "4":
        # Perform all scans
        process_logs, suspicious_files = scan_processes()
        all_logs.extend(process_logs)
        if suspicious_files:
            all_logs.extend(analyze_suspicious_files(suspicious_files, known_hashes))

        print("[+] Scanning the entire OS file tree. This may take some time...")
        for root_dir in ["C:/" if os.name == "nt" else "/"]:  # Adjust root directory based on OS
            all_logs.extend(scan_files(root_dir, known_hashes))
        all_logs.extend(scan_network_connections())
    else:
        print("[!] Invalid choice. Please select a valid option.")

    # Log results to a report file
    if all_logs:
        log_report(all_logs)
    else:
        print("[!] No logs generated. No threats detected or scans performed.")

if __name__ == "__main__":
    main()

