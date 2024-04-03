import ansible_runner
import json
from map.models import Org_Info

class AnsiblePlaybookRunError(Exception):
    pass

def run_ansible_playbook(playbook):
    """
    Run an Ansible playbook and return the data

    Args:
    - playbook (str): Name of the Ansible playbook file (without the .yml extension).
    """
    org_info = Org_Info.objects.get()
    ansible_config = {
        'ansible_network_os': 'ios',
        'ansible_connection': 'network_cli',
        'ansible_user': org_info.ssh_username,
        'ansible_ssh_pass': org_info.ssh_password,
        'ansible_become': 'yes',
        'ansible_become_method': 'enable',
        'ansible_become_pass': org_info.ssh_enable_password,
    }
    output = {
        "runner_on_ok": [],
        "runner_on_failed": []
    }
    try:
        r = ansible_runner.run(
            private_data_dir='/home/sbs/Dash/ansible/',
            playbook=f'/home/sbs/Dash/ansible/{playbook}.yml',
            inventory='/home/sbs/Dash/ansible/hosts.ini',
            quiet=True,
            extravars=ansible_config,
            suppress_env_files=True
        )
        for i in r.events:
            if i['event'] == 'runner_on_ok':
                completed_task = {
                    "hostname": i['event_data']['host'],
                    "task_name": i['event_data']['task'],
                    "task_result": i['event_data']['res']
                }
                output["runner_on_ok"].append(completed_task)
            if i['event'] == 'runner_on_failed':
                failed_task = {
                    "hostname": i['event_data']['host'],
                    "task_name": i['event_data']['task'],
                    "task_result": i['event_data']['res']
                }
                output["runner_on_failed"].append(failed_task)
            elif i['event'] == 'warning' and '[WARNING]: Could not match supplied host pattern, ignoring: network_devices' in i['stdout']:
                raise AnsiblePlaybookRunError("Host Pattern Not Found")
        return(output)
    except FileNotFoundError as fnf_err:
        raise AnsiblePlaybookRunError(f"File not found error: {str(fnf_err)}")
    except AnsiblePlaybookRunError as e:
        raise e
    except Exception as e:
        raise AnsiblePlaybookRunError(f"An error occurred: {str(e)}")
