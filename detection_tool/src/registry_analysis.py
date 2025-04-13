import winreg

def analyze_registry():
    """
    Analyze the Windows registry for unauthorized or modified entries related to user privileges.

    Returns:
        dict: A dictionary containing suspicious registry entries and their details.
    """
    suspicious_entries = {}

    # Define registry keys to check
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
    ]

    try:
        for hive, path in registry_paths:
            try:
                with winreg.OpenKey(hive, path) as key:
                    i = 0
                    while True:
                        try:
                            value_name, value_data, _ = winreg.EnumValue(key, i)
                            # Check for suspicious entries (e.g., unexpected executables or scripts)
                            if "cmd.exe" in value_data.lower() or "powershell.exe" in value_data.lower():
                                suspicious_entries[f"{path}\\{value_name}"] = value_data
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                continue
    except Exception as e:
        suspicious_entries["Error"] = f"Error analyzing registry: {e}"

    return suspicious_entries