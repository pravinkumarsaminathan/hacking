import os
import stat

def analyze_file_permissions(paths_to_check):
    """
    Analyze file and directory permissions for potential vulnerabilities.
    
    Args:
        paths_to_check (list): List of file or directory paths to analyze.
    
    Returns:
        dict: A dictionary with file/directory paths as keys and their permission issues as values.
    """
    permission_issues = {}

    for path in paths_to_check:
        if not os.path.exists(path):
            permission_issues[path] = "Path does not exist"
            continue

        try:
            st = os.stat(path)
            #os.stat_result(st_mode=16877, st_ino=16386, st_dev=2112, st_nlink=3, st_uid=0, st_gid=0, st_size=4096, st_atime=1744269365, st_mtime=1716014143, st_ctime=1716014143)
            mode = st.st_mode

            # Check for world-writable files or directories
            if bool(mode & stat.S_IWOTH):
                permission_issues[path] = "World-writable (insecure permissions)"
            
            # Check for world-readable sensitive files
            if os.path.isfile(path) and bool(mode & stat.S_IROTH):
                permission_issues[path] = "World-readable (potentially sensitive file)"
        except Exception as e:
            permission_issues[path] = f"Error analyzing permissions: {e}"

    return permission_issues