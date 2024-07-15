import ldap
from django_auth_ldap.config import LDAPSearch, LDAPSearchUnion
from map.models import LdapAccount
import subprocess
import logging
import time
logger_network = logging.getLogger('map')

def get_ldap_settings():
    ldap_obj = LdapAccount.objects.get()

    settings = {
        "AUTH_LDAP_SERVER_URI": f"ldap://{ldap_obj.dc_ip_address}",
        "AUTH_LDAP_BIND_DN": ldap_obj.bind_account,
        "AUTH_LDAP_BIND_PASSWORD": ldap_obj.bind_password,
        "AUTH_LDAP_USER_SEARCH": rf'''LDAPSearchUnion(LDAPSearch(f"{ldap_obj.tech_group}",ldap.SCOPE_SUBTREE,"(sAMAccountName=%(user)s)"),LDAPSearch(f"{ldap_obj.admin_group}",ldap.SCOPE_SUBTREE,"(sAMAccountName=%(user)s)"))''',
    }

    return settings

def update_settings(new_settings):
    file_path = '/home/sbs/Dash/dash/settings.py'
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        changes = []
        for key, value in new_settings.items():
            for i, line in enumerate(lines):
                if key in line:
                    old_value = line.split('=')[1].strip()
                    if key != 'AUTH_LDAP_USER_SEARCH':
                        lines[i] = f"{key} = '{value}'\n"
                    else:
                        lines[i] = f"{key} = {value}\n"
                    changes.append(f"Changed {key} from '{old_value}' to '{value}'")

        with open(file_path, 'w') as f:
            f.writelines(lines)

        print("Settings updated successfully.")
        if changes:
            print("Changes made:")
            for change in changes:
                print(change)

    except Exception as e:
        print(f"Error updating settings: {e}")

def reboot_gunicorn():
    try:
        subprocess.run(['sudo', 'systemctl', 'restart', 'gunicorn.service'])
        print("Server restarted successfully.")
    except Exception as e:
        print(f"Error restarting server: {e}")



def reboot_celery():
    services = [
        'celery_api.service',
        'celery_worker_configure.service',
        'celery_worker_get_info.service',
        'celery_beat.service',
        'celery_worker_ping.service'
    ]

    for service in services:
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', service], check=True)
            logger_network.info(f"{service} restarted successfully.")
            # Add a delay between restarts to avoid hitting the start limit
            time.sleep(5)
        except subprocess.CalledProcessError as e:
            logger_network.error(f"Error restarting {service}: {e}")
        except Exception as e:
            logger_network.error(f"Unexpected error: {e}")