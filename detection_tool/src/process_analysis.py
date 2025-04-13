import psutil
import platform

def analyze_processes():
    """
    Analyze running processes to identify suspicious or unauthorized processes with elevated privileges.

    Returns:
        list: A list of dictionaries containing details of suspicious processes.
    """
    suspicious_processes = []
    is_windows = platform.system() == "Windows"

    try:
        # Only include 'uids' on non-Windows systems
        attrs = ['pid', 'name', 'username']
        if not is_windows:
            attrs.append('uids')

        for proc in psutil.process_iter(attrs):
            try:
                process_info = proc.info

                if is_windows:
                    # On Windows, flag processes running as SYSTEM (elevated)
                    if process_info['username'] and "SYSTEM" in process_info['username']:
                        suspicious_processes.append({
                            "pid": process_info['pid'],
                            "name": process_info['name'],
                            "username": process_info['username'],
                            "privilege": "SYSTEM (Elevated)"
                        })
                else:
                    # On Linux/macOS, check if UID is 0 (root)
                    if process_info.get('uids') and process_info['uids'].real == 0:
                        suspicious_processes.append({
                            "pid": process_info['pid'],
                            "name": process_info['name'],
                            "username": process_info['username'],
                            "privilege": "Root (Elevated)"
                        })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    except Exception as e:
        print(f"Error analyzing processes: {e}")

    return suspicious_processes
