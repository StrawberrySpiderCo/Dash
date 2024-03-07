import socket
import re

def get_system_ip():
    """Get the private IP address of the system."""
    try:
        # Get the private IP address assigned to the default interface
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
        return ip_address
    except Exception as e:
        print("Error:", e)
        return None

def update_settings_file(ip_address, settings_file_path):
    """Update the Django settings file with the server's IP address."""
    try:
        # Read the content of the settings file
        with open(settings_file_path, 'r') as f:
            settings_content = f.read()
        # Replace the CSRF_TRUSTED_ORIGINS setting with the updated IP address
        updated_content = re.sub(
            r"CSRF_TRUSTED_ORIGINS\s*=\s*\[.*?\]",
            f"CSRF_TRUSTED_ORIGINS = ['http://{ip_address}']",
            settings_content,
            flags=re.DOTALL
        )
        # Write the updated content back to the settings file
        with open(settings_file_path, 'w') as f:
            f.write(updated_content)
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    # Get the server's IP address
    server_ip = get_system_ip()
    if server_ip:
        # Update the Django settings file
        update_settings_file(server_ip, '/home/sbs/Dash/dash/settings.py')
