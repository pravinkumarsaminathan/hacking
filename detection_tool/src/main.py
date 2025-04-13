import os
import platform
from privilege_analysis import analyze_privileges
from file_permission_analysis import analyze_file_permissions
from process_analysis import analyze_processes
from log_analysis import analyze_logs
if platform.system() == "Windows":
    from registry_analysis import analyze_registry
    from win_privilege_analysis import analyze_privileges

def main():
    print("Starting Escalation Detection Tool...")
    
    print("\nPrivilege Analysis Results:")
    if platform.system() != "Windows":
        # Analyze current user's privileges
        elevated_privileges = analyze_privileges()
    else:
        elevated_privileges = analyze_privileges()
        
    if elevated_privileges:
        for privilege, has_access in elevated_privileges.items():
            status = "Yes" if has_access else "No"
            print(f"{privilege.replace('_', ' ').title()}: {status}")
    else:
            print("No elevated privileges detected. System appears secure.")
    
    # Analyze file and directory permissions
    print("\nFile and Directory Permission Analysis:")
    if platform.system() != "Windows":
        critical_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/root",
        "/home",
        "/var/log",
        ]
    else:
        critical_paths = [
        #"C:\\Windows\\System32\\config\\SAM",            # Stores user account info (Security Account Manager)
        #"C:\\Windows\\System32\\config\\SYSTEM",         # Contains system configuration and driver info
        #"C:\\Windows\\System32\\config\\SECURITY",       # Local security policy data
        #"C:\\Windows\\System32\\config\\SOFTWARE",       # Software and registry hives
        "C:\\Users\\Administrator",                      # Admin user profile
        "C:\\Users\\Public",                             # Public user profile
        "C:\\Users\\<USERNAME>\\AppData\\Roaming",       # Per-user app data (good for malware persistence)
        "C:\\Users\\<USERNAME>\\AppData\\Local\\Temp",   # Temp files often abused by malware
        "C:\\Windows\\Temp",                             # System-wide temp files
        "C:\\Windows\\Prefetch",                         # Execution trace of recently used apps
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",  # Auto-start apps
        "C:\\Program Files",                             # Installed programs (x64)
        "C:\\Program Files (x86)",                       # Installed programs (x86)
        "C:\\Windows\\System32\\Tasks",                  # Scheduled tasks
        "C:\\Windows\\System32\\drivers\\etc\\hosts",    # Hosts file, often hijacked
        "C:\\Windows\\Logs",                             # General logs
        "C:\\Windows\\System32\\winevt\\Logs",           # Windows event logs (.evtx files)
    ]

    permission_issues = analyze_file_permissions(critical_paths)
    
    if permission_issues:
        for path, issue in permission_issues.items():
            print(f"{path}: {issue}")
    else:
        print("No permission issues detected.")
    
    # Analyze running processes
    print("\nProcess Analysis:")
    suspicious_processes = analyze_processes()
    
    if suspicious_processes:
        print("Suspicious Processes Detected:")
        for process in suspicious_processes:
            print(f"PID: {process['pid']}, Name: {process['name']}, User: {process['username']}, Privilege: {process['privilege']}")
    else:
        print("No suspicious processes detected.")
    
    # Analyze registry entries
    print("\nRegistry Analysis:")
    if platform.system() == "Windows":
        suspicious_registry_entries = analyze_registry()
    
        if suspicious_registry_entries:
            print("Suspicious Registry Entries Detected:")
            for entry, value in suspicious_registry_entries.items():
                print(f"{entry}: {value}")
        else:
            print("No suspicious registry entries detected.")
    else:
        print("This functionality is specific to Windows systems, as Linux does not use a registry.")

    # Analyze system logs
    print("\nLog Analysis:")
    suspicious_logs = analyze_logs()
    
    if suspicious_logs:
        print("Suspicious Log Entries Detected:")
        for log in suspicious_logs:
            print(log)
    else:
        print("No suspicious log entries detected.")

if __name__ == "__main__":
    main()