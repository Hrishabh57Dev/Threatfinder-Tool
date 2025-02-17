import os
import psutil
import hashlib
import datetime
import requests  # For fetching malware hashes from external sources
import pefile  # For analyzing PE files
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # For disassembly
import platform
import subprocess

# File containing known malware hashes
MALWARE_HASHES_FILE = "malwarehashes.txt"
SUSPICIOUS_CPU_THRESHOLD = 80.0  # CPU usage percentage
SUSPICIOUS_MEMORY_THRESHOLD = 100 * 1024 * 1024  # Memory usage in bytes (100 MB)

MALSHARE_API_KEY = "a8e72bc66ce15f320a283783f16763d8b51d337c3ff36c223553f41d684eb8a0"
MALSHARE_API_URL = "https://malshare.com/api.php"


def fetch_latest_hashes():
    """Fetch the latest malware hashes from the Malshare API."""
    print("[+] Fetching latest malware hashes from Malshare...")
    try:
        response = requests.get(MALSHARE_API_URL, params={"api_key": MALSHARE_API_KEY, "action": "getlist"})
        if response.status_code == 200:
            latest_hashes = response.text.splitlines()
            latest_hashes = remove_duplicates(latest_hashes)
            with open(MALWARE_HASHES_FILE, "w") as f:
                f.write("\n".join(latest_hashes))
            print(f"[+] Updated {MALWARE_HASHES_FILE} with {len(latest_hashes)} unique hashes.")
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
    """Scan running processes for anomalies on both Windows and Linux."""
    logs = ["[Process Scan Report]"]
    suspicious_files = []

    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'memory_info', 'cpu_percent', 'exe']):
        try:
            proc_info = proc.info
            file_path = proc_info.get('exe', None)

            # Check for suspicious CPU or memory usage
            if proc_info['cpu_percent'] > SUSPICIOUS_CPU_THRESHOLD or \
               (proc_info['memory_info'] and proc_info['memory_info'].rss > SUSPICIOUS_MEMORY_THRESHOLD):
                logs.append(
                    f"[SUSPICIOUS PROCESS] PID: {proc_info['pid']}, Name: {proc_info['name']}, "
                    f"Path: {file_path}, CPU: {proc_info['cpu_percent']}%, Memory: {proc_info['memory_info'].rss} bytes"
                )
                if file_path:
                    suspicious_files.append(file_path)
            else:
                logs.append(
                    f"PID: {proc_info['pid']}, Name: {proc_info['name']}, Path: {file_path}, "
                    f"User: {proc_info['username']}"
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Add OS-specific commands to enhance the analysis
    if platform.system() == "Windows":
        logs.extend(scan_windows_processes())
    elif platform.system() == "Linux":
        logs.extend(scan_linux_processes())

    return logs, suspicious_files


def scan_windows_processes():
    """Use WMIC to get additional details about processes on Windows."""
    logs = ["[Windows Process Details]"]
    try:
        result = subprocess.run(["wmic", "process", "get", "name,executablepath"], capture_output=True, text=True)
        if result.returncode == 0:
            process_details = result.stdout.strip().splitlines()
            logs.extend(process_details)
        else:
            logs.append(f"[!] WMIC command failed: {result.stderr}")
    except Exception as e:
        logs.append(f"[!] Error running WMIC: {e}")
    return logs


def scan_linux_processes():
    """Use lsof and ps commands to get additional details about processes on Linux."""
    logs = ["[Linux Process Details]"]
    try:
        lsof_result = subprocess.run(["lsof", "-nP"], capture_output=True, text=True)
        if lsof_result.returncode == 0:
            logs.append("[+] lsof Output:")
            logs.extend(lsof_result.stdout.strip().splitlines())
        else:
            logs.append(f"[!] lsof command failed: {lsof_result.stderr}")

        ps_result = subprocess.run(["ps", "-eo", "pid,comm,args"], capture_output=True, text=True)
        if ps_result.returncode == 0:
            logs.append("[+] ps Output:")
            logs.extend(ps_result.stdout.strip().splitlines())
        else:
            logs.append(f"[!] ps command failed: {ps_result.stderr}")
    except Exception as e:
        logs.append(f"[!] Error running Linux commands: {e}")
    return logs


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


def main():
    fetch_latest_hashes()

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
    elif choice == "2":
        all_logs.extend(scan_network_connections())
    elif choice == "3":
        directory = input("Enter directory to scan: ")
        if os.path.isdir(directory):
            all_logs.extend(scan_files(directory, known_hashes))
        else:
            print("[!] Invalid directory")
    elif choice == "4":
        process_logs, suspicious_files = scan_processes()
        all_logs.extend(process_logs)
        directory = input("Enter directory to scan: ")
        if os.path.isdir(directory):
            all_logs.extend(scan_files(directory, known_hashes))
        else:
            print("[!] Invalid directory")
        all_logs.extend(scan_network_connections())
    else:
        print("[!] Invalid choice. Please select a valid option.")

    if all_logs:
        log_report(all_logs)
    else:
        print("[!] No logs generated. No threats detected or scans performed.")


if __name__ == "__main__":
    main()
This version ensures Windows (WMIC) and Linux (lsof and ps) compatibility for process scanning. Let me know if additional features are needed!






You said:
perform all scan should do to whole tree of os to find suspicious files 
ChatGPT said:
Here's the updated version of the tool where the "Perform All Scans" option scans the entire file system (or a specific root directory) to search for suspicious files. This modification ensures the script recursively scans all accessible directories in the OS, starting from / in Linux or C:\ in Windows.

Additionally, the process scanning, network connection scanning, and file scanning are integrated into the "Perform All Scans" functionality.

Updated Code:
python
Copy
Edit
import os
import psutil
import hashlib
import datetime
import requests  # For fetching malware hashes from external sources
import platform
import subprocess

# File containing known malware hashes
MALWARE_HASHES_FILE = "malwarehashes.txt"
SUSPICIOUS_CPU_THRESHOLD = 80.0  # CPU usage percentage
SUSPICIOUS_MEMORY_THRESHOLD = 100 * 1024 * 1024  # Memory usage in bytes (100 MB)

MALSHARE_API_KEY = "a8e72bc66ce15f320a283783f16763d8b51d337c3ff36c223553f41d684eb8a0"
MALSHARE_API_URL = "https://malshare.com/api.php"


def fetch_latest_hashes():
    """Fetch the latest malware hashes from the Malshare API."""
    print("[+] Fetching latest malware hashes from Malshare...")
    try:
        response = requests.get(MALSHARE_API_URL, params={"api_key": MALSHARE_API_KEY, "action": "getlist"})
        if response.status_code == 200:
            latest_hashes = response.text.splitlines()
            latest_hashes = remove_duplicates(latest_hashes)
            with open(MALWARE_HASHES_FILE, "w") as f:
                f.write("\n".join(latest_hashes))
            print(f"[+] Updated {MALWARE_HASHES_FILE} with {len(latest_hashes)} unique hashes.")
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
    """Scan running processes for anomalies on both Windows and Linux."""
    logs = ["[Process Scan Report]"]
    suspicious_files = []

    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'memory_info', 'cpu_percent', 'exe']):
        try:
            proc_info = proc.info
            file_path = proc_info.get('exe', None)

            # Check for suspicious CPU or memory usage
            if proc_info['cpu_percent'] > SUSPICIOUS_CPU_THRESHOLD or \
               (proc_info['memory_info'] and proc_info['memory_info'].rss > SUSPICIOUS_MEMORY_THRESHOLD):
                logs.append(
                    f"[SUSPICIOUS PROCESS] PID: {proc_info['pid']}, Name: {proc_info['name']}, "
                    f"Path: {file_path}, CPU: {proc_info['cpu_percent']}%, Memory: {proc_info['memory_info'].rss} bytes"
                )
                if file_path:
                    suspicious_files.append(file_path)
            else:
                logs.append(
                    f"PID: {proc_info['pid']}, Name: {proc_info['name']}, Path: {file_path}, "
                    f"User: {proc_info['username']}"
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Add OS-specific commands to enhance the analysis
    if platform.system() == "Windows":
        logs.extend(scan_windows_processes())
    elif platform.system() == "Linux":
        logs.extend(scan_linux_processes())

    return logs, suspicious_files


def scan_windows_processes():
    """Use WMIC to get additional details about processes on Windows."""
    logs = ["[Windows Process Details]"]
    try:
        result = subprocess.run(["wmic", "process", "get", "name,executablepath"], capture_output=True, text=True)
        if result.returncode == 0:
            process_details = result.stdout.strip().splitlines()
            logs.extend(process_details)
        else:
            logs.append(f"[!] WMIC command failed: {result.stderr}")
    except Exception as e:
        logs.append(f"[!] Error running WMIC: {e}")
    return logs


def scan_linux_processes():
    """Use lsof and ps commands to get additional details about processes on Linux."""
    logs = ["[Linux Process Details]"]
    try:
        lsof_result = subprocess.run(["lsof", "-nP"], capture_output=True, text=True)
        if lsof_result.returncode == 0:
            logs.append("[+] lsof Output:")
            logs.extend(lsof_result.stdout.strip().splitlines())
        else:
            logs.append(f"[!] lsof command failed: {lsof_result.stderr}")

        ps_result = subprocess.run(["ps", "-eo", "pid,comm,args"], capture_output=True, text=True)
        if ps_result.returncode == 0:
            logs.append("[+] ps Output:")
            logs.extend(ps_result.stdout.strip().splitlines())
        else:
            logs.append(f"[!] ps command failed: {ps_result.stderr}")
    except Exception as e:
        logs.append(f"[!] Error running Linux commands: {e}")
    return logs


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


def main():
    fetch_latest_hashes()
    known_hashes = load_known_hashes()

    if not known_hashes:
        print("[!] No known malware hashes loaded. Aborting scans.")
        return

    print("ThreatFinder - Lightweight Threat Detection Tool")
    print("1. Scan Processes")
    print("2. Scan Network Connections")
    print("3. Scan Specific Directory")
    print("4. Perform All Scans (Full System)")
    choice = input("Enter your choice: ")

    all_logs = []

    if choice == "1":
        process_logs, suspicious_files = scan_processes()
        all_logs.extend(process_logs)
    elif choice == "2":
        all_logs.extend(scan_network_connections())
    elif choice == "3":
        directory = input("Enter directory to scan: ")
        if os.path.isdir(directory):
            all_logs.extend(scan_files(directory, known_hashes))
        else:
            print("[!] Invalid directory.")
    elif choice == "4":
        # Full system scan: all processes, network connections, and files
        print("[+] Scanning processes...")
        process_logs, suspicious_files = scan_processes()
        all_logs.extend(process_logs)

        print("[+] Scanning network connections...")
        all_logs.extend(scan_network_connections())

        root_directory = "C:\\" if platform.system() == "Windows" else "/"
        print(f"[+] Scanning all files from root directory: {root_directory}...")
        all_logs.extend(scan_files(root_directory, known_hashes))
    else:
        print("[!] Invalid choice. Please select a valid option.")

    if all_logs:
        log_report(all_logs)
    else:
        print("[!] No logs generated. No threats detected or scans performed.")


if __name__ == "__main__":
    main()