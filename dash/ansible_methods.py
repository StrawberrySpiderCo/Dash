import ansible_runner
import json
from map.models import Org_Info,NetworkDevice,NetworkInterface,NetworkTask,NetworkAccount
import os
import shutil
import logging
import subprocess
logger_network = logging.getLogger('network')
playbookPath = r'/home/sbs/Dash/ansible/'
private_data_path = r'/home/sbs/Dash/ansible/'
inventory_path = r'/home/sbs/Dash/ansible/hosts.ini'
class AnsiblePlaybookRunError(Exception):
    pass
def update_host_file_ping(online_devices):
    playbook_dir = '/home/sbs/Dash/ansible'
    host_file_path = f"{playbook_dir}/hosts.ini"
    with open(host_file_path, 'w') as host_file:
        host_file.write("[network_devices]\n")
        for ip in online_devices:
            logger_network.info(f"Writing {ip} to host file")
            host_file.write(f"{ip} ansible_host={ip}\n")    
        host_file.write("\n[network_devices:vars]\n")
        host_file.write("ansible_network_os=ios\n")
        host_file.write("ansible_connection=network_cli\n")
def update_host_file():
    playbook_dir = '/home/sbs/Dash/ansible'
    host_file_path = f"{playbook_dir}/hosts.ini"
    online_devices = {device.ip_address for device in NetworkDevice.objects.filter(online=True)}
    with open(host_file_path, 'w') as host_file:
        host_file.write("[network_devices]\n")
        for ip in online_devices:
            logger_network.info(f"Writing {ip} to host file")
            host_file.write(f"{ip} ansible_host={ip}\n")
        host_file.write("\n[network_devices:vars]\n")
        host_file.write("ansible_network_os=ios\n")
        host_file.write("ansible_connection=network_cli\n")


        
def run_ansible_playbook(task_name, ansible_config):
    """
    Run an Ansible task and return the data

    Args:
    - task_name (str): Name of the Ansible task.
    - ansible_config (dict): Configuration parameters for Ansible.
    - EXAMPLE: r,output = run_ansible_playbook('set_interfaceShut', {'hostname':hostname, 'interface_name': interface, 'input_action':action})

    Output:
    - returns 2 variables
    - r (runner): runner instance, used to grab status codes, verbose event data, etc
    - output (dict): returns a dictionary contains simplified data to return to user if nessesary
    {
    'runner_on_ok': {
        'hostname': '',
        'task_name': '',
        'task_result': ''
        },
    'runner_on_fail': {
        'hostname': '',
        'task_name': '',
        'task_result': ''
        }
    }
    """
    org_info = NetworkAccount.objects.get()
    ansible_config.update({
        'ansible_network_os': 'ios',
        'ansible_connection': 'network_cli',
        'ansible_user': org_info.ssh_username,
        'ansible_ssh_pass': org_info.ssh_password,
        'ansible_become': 'yes',
        'ansible_become_method': 'enable',
        'ansible_become_pass': org_info.ssh_enable_password,
    })
    output = {
        "runner_on_ok": [],
        "runner_on_failed": []
    }
    try:
        r = ansible_runner.run(
            private_data_dir='/home/sbs/Dash/ansible/',
            playbook=f'/home/sbs/Dash/ansible/{task_name}.yml',
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
        return (r, output)
    except FileNotFoundError as fnf_err:
        raise AnsiblePlaybookRunError(f"File not found error: {str(fnf_err)}")
    except AnsiblePlaybookRunError as e:
        raise e
    except Exception as e:
        raise AnsiblePlaybookRunError(f"An error occurred: {str(e)}")

def ansible_logging(events):
    """
    Run after run_ansible_playbook to save results to the database. The reason this is not integrated in the main method is to setup better logging solution in the future without
    disrupting run_ansible_playbook

    Args:
    - events (r.events) - after running run_ansible_playbook you will have access to the the runner output and will have to run that in the r.events then input that
    - EXAMPLE:      r,output = run_ansible_playbook('set_l2interface', {'hostname':hostname, 'interface_name': interface, 'switchport_mode': mode, 'vlan_id': vlan, 'voice_vlan': voice_vlan, 'native_vlan': native_vlan, 'allowed_vlans': allowed_vlan,'encapsulation': encapsulation})
                    events = r.events
                    ansible_logging(events)


    Output:
    - provides no output but will log all events provided into Postgres database under network tasks
    """
    #output = {
    #    "runner_on_ok": [],
    #    "runner_on_failed": []
    #}
    for i in events:
            if i['event'] == 'runner_on_ok':
                duration = i['event_data']['duration']
                try:
                    msg = i['event_data']['res']['results'][0]['msg']
                except (KeyError, IndexError):
                    try:
                        msg = i['event_data']['res']['msg']
                    except KeyError:
                        try:
                            msg = i['event_data']['msg']
                        except KeyError:
                            msg = f'Task Done: {duration}secs'
                start_time_list = (i['event_data']['start']).split('.')
                start_time = start_time_list[0]
                net_device = NetworkDevice.objects.get(ip_address=i['event_data']['host'])
                NetworkTask.objects.create(
                device=net_device,
                result = 'Successful',
                start_time = start_time,
                end_time = i['event_data']['end'],
                duration = duration,
                name = i['event_data']['task'],
                uid = i['event_data']['uuid'],
                task_result = i['event_data']['res'],
                msg = msg,
            )
                #completed_task = {
                #    "hostname": i['event_data']['host'],
                #    "task_name": i['event_data']['task'],
                #    "task_result": i['event_data']['res'],
                #    "start_time": i['event_data']['start'],
                #    "end_time": i['event_data']['end'],
                #    "duration": i['event_data']['duration']
                #}
                #output["runner_on_ok"].append(completed_task)
            if i['event'] == 'runner_on_failed':
                duration = i['event_data']['duration']
                try:
                    msg = i['event_data']['res']['results'][0]['msg']
                except (KeyError, IndexError):
                    try:
                        msg = i['event_data']['res']['msg']
                    except KeyError:
                        try:
                            msg = i['event_data']['msg']
                        except KeyError:
                            msg = f'Task Timed Out: {duration}secs'
                start_time_list = (i['event_data']['start']).split('.')
                start_time = start_time_list[0]
                net_device = NetworkDevice.objects.get(ip_address=i['event_data']['host'])
                NetworkTask.objects.create(
                device=net_device,
                result = 'Failed',
                start_time = start_time,
                end_time = i['event_data']['end'],
                duration = duration,
                name = i['event_data']['task'],
                uid = i['event_data']['uuid'],
                task_result =  i['event_data']['res'],
                msg = msg
            )
                #failed_task = {
                #    "hostname": i['event_data']['host'],
                #    "task_name": i['event_data']['task'],
                #    "task_result": i['event_data']['res'],
                #    "start_time": i['event_data']['start'],
                #    "end_time": i['event_data']['end'],
                #    "duration": i['event_data']['duration']
                #}
                #output["runner_on_failed"].append(failed_task)

def cleanup_artifacts_folder():
    artifacts_folder = '/home/sbs/Dash/ansible/artifacts'
    env_path = '/home/sbs/Dash/ansible/env/extravars'
    try:
        # Delete the entire artifacts folder and its contents
        shutil.rmtree(artifacts_folder)
        logger_network.info("Artifacts folder deleted successfully.")
    except FileNotFoundError:
        logger_network.info("Artifacts folder already deleted.")
    except Exception as e:
        logger_network.error(f"Error deleting artifacts folder: {e}")

    try:
        os.remove(env_path)
        logger_network.info("Env file deleted successfully.")
    except FileNotFoundError:
        logger_network.info("Env file already deleted.")
    except Exception as e:
        logger_network.error(f"Error deleting env file: {e}")