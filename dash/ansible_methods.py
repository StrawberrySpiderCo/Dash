import ansible_runner
import json
from map.models import Org_Info,NetworkDevice,NetworkInterface,NetworkTask
import shutil
from typing import Literal, Union, Optional
import os

class AnsiblePlaybookRunError(Exception):
    pass

def ansible_logging(events):
    output = {
        "runner_on_ok": [],
        "runner_on_failed": []
    }
    for i in events:
            if i['event'] == 'runner_on_ok':
                net_device = NetworkDevice.objects.get(ip_address=i['event_data']['host'])
                NetworkTask.objects.create(
                device=net_device,
                result = 'Successful',
                start_time = i['event_data']['start'],
                end_time = i['event_data']['end'],
                duration = i['event_data']['duration'],
                name = i['event_data']['task'],
                uid = i['event_data']['uuid'],
                task_result = i['event_data']['res']
            )
                completed_task = {
                    "hostname": i['event_data']['host'],
                    "task_name": i['event_data']['task'],
                    "task_result": i['event_data']['res'],
                    "start_time": i['event_data']['start'],
                    "end_time": i['event_data']['end'],
                    "duration": i['event_data']['duration']
                }
                output["runner_on_ok"].append(completed_task)
            if i['event'] == 'runner_on_failed':
                net_device = NetworkDevice.objects.get(ip_address=i['event_data']['host'])
                NetworkTask.objects.create(
                device=net_device,
                result = 'Failed',
                start_time = i['event_data']['start'],
                end_time = i['event_data']['end'],
                duration = i['event_data']['duration'],
                name = i['event_data']['task'],
                uid = i['event_data']['uuid'],
            )
                failed_task = {
                    "hostname": i['event_data']['host'],
                    "task_name": i['event_data']['task'],
                    "task_result": i['event_data']['res'],
                    "start_time": i['event_data']['start'],
                    "end_time": i['event_data']['end'],
                    "duration": i['event_data']['duration']
                }
                output["runner_on_failed"].append(failed_task)
    print(type(output))

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
            suppress_env_files=True,
        )
        events = r.events
        ansible_logging(events)
        cleanup_artifacts_folder()
    except FileNotFoundError as fnf_err:
        raise AnsiblePlaybookRunError(f"File not found error: {str(fnf_err)}")
    except AnsiblePlaybookRunError as e:
        raise e
    except Exception as e:
        raise AnsiblePlaybookRunError(f"An error occurred: {str(e)}")


def cleanup_artifacts_folder():
    artifacts_folder = '/home/sbs/Dash/ansible/artifacts'
    env_path = '/home/sbs/Dash/ansible/env/extravars'
    try:
        # Delete the entire artifacts folder and its contents
        shutil.rmtree(artifacts_folder)
        print("Artifacts folder deleted successfully.")
    except Exception as e:
        print(f"Error deleting artifacts folder: {e}")
    try:
        os.remove(env_path)
    except Exception as e:
        print(f"Error deleting env file: {e}")


## FROM Dirar's Ansible Method ##
playbookPath = r'/home/sbs/Dash/ansible/'
private_data_path = r'/home/sbs/Dash/ansible/'
inventory_path = r'/home/sbs/Dash/ansible/hosts.ini'

def getAnsibleConfig(append_config = {}):
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
    ansible_config.update(append_config)
    return ansible_config

def getSystemInfo(ansibleHost):
    r = ansible_runner.run(private_data_dir=private_data_path,
                        playbook=rf'{playbookPath}get_systemInfo.yml',
                        inventory=inventory_path,
                        quiet=True,
                        extravars=getAnsibleConfig({'hostname': ansibleHost},))

    for i in r.events:
        if i['event'] == 'runner_on_ok':
            res = i['event_data']['res']    
               
    if 'res' in locals():
        resJson = json.dumps(res)
        resJson = json.loads(resJson)
        systemInfo = resJson["ansible_facts"]#["ansible_net_hostname"]
        return systemInfo
    else:
        raise Exception([item for item in r.events])

def setShut(ansibleHost: str,
            interface: Union[list, str],
            isShut: Literal['shut','noshut']):
    if type(interface) == str:
        interface = [interface]
    org_info = Org_Info.objects.get()

    r = ansible_runner.run(private_data_dir=private_data_path,
                           playbook=rf'{playbookPath}set_interfaceShut.yml',
                           inventory=inventory_path,
                           quiet=True,
                           extravars={
                                    'ansible_network_os': 'ios',
                                    'ansible_connection': 'network_cli',
                                    'ansible_user': org_info.ssh_username,
                                    'ansible_ssh_pass': org_info.ssh_password,
                                    'ansible_become': 'yes',
                                    'ansible_become_method': 'enable',
                                    'ansible_become_pass': org_info.ssh_enable_password,
                                    'hostname':ansibleHost,
                                    'input_action':isShut,
                                    'interface_name':interface,})
    events = r.events
    ansible_logging(events)
    cleanup_artifacts_folder()
                                      
    
def l2interface(hostname: str, 
                interface: list, 
                mode: Literal['access', 'trunk', 'delete'], 
                vlan: Optional[int] = 'None', 
                voice_vlan: Optional[int] = 'None',
                native_vlan: Optional[int] = 'None',
                allowed_vlan: Optional[list] = 'None',
                encapsulation: Literal['dot1q', 'isl', 'negotiate'] = 'dot1q'):

    ### Parameter Checking Start ## 
    #if type(interface) != list:
    #    if type(interface) == str:
    #        interface = [interface]
    #    else:
    #        raise ValueError(f'Parameter must be type list\nValue: {interface}\nType: {type(interface)}')
    #if mode not in ['access', 'trunk', 'delete']:
    #    return json.dumps({'Error': f'Mode was not set to one of the define values. Mode = {mode}'})
    #paramList_int = [vlan, voice_vlan, native_vlan]
    #for i in paramList_int:
    #    if i != "None" and not isinstance(i, int):
    #        raise ValueError(f'Parameter must be "None" or type int\nValue: {i}\nType: {type(i)}')
    #if not isinstance(allowed_vlan, list) and allowed_vlan != 'None':
    #    raise ValueError(f'Parameter must be "None" or type list\nValue: {allowed_vlan}\nType: {type(allowed_vlan)}')
    #elif isinstance(allowed_vlan, list):
    #    for i in allowed_vlan:
    #        if not isinstance(i, str):
    #            raise ValueError(f'Parameter must be "None" or type str\nValue: {i}\nType: {type(i)}')
    ### Parameter Checking End ##
    org_info = Org_Info.objects.get()
    r = ansible_runner.run(private_data_dir=private_data_path,
                           playbook=rf'{playbookPath}set_l2interface.yml',
                           inventory=inventory_path,
                           quiet=True,
                           extravars={
                                    'ansible_network_os': 'ios',
                                    'ansible_connection': 'network_cli',
                                    'ansible_user': org_info.ssh_username,
                                    'ansible_ssh_pass': org_info.ssh_password,
                                    'ansible_become': 'yes',
                                    'ansible_become_method': 'enable',
                                    'ansible_become_pass': org_info.ssh_enable_password,
                                    'hostname': hostname,
                                    'interface_name': interface,
                                    'switchport_mode': mode,
                                    'vlan_id': vlan,
                                    'voice_vlan': voice_vlan,
                                    'native_vlan': native_vlan,
                                    'allowed_vlans': allowed_vlan,
                                    'encapsulation': encapsulation})
    events = r.events
    ansible_logging(events)
    cleanup_artifacts_folder()
def l3interface(hostname: str = '',
                interface: list = [],
                ipv4: dict = {
                    "ip_address": None,
                    "mask": None,
                    "is_ipv4": False,
                    "is_secondIP": False,
                    "is_dhcp": False,
                    "client_id": None,
                    "hostname": None,},
                ipv6: dict = {
                    "address": None,
                    "mask": None,
                    "is_anycast": None,
                    "is_autoconfigDefault": None,
                    "is_autoconfigEnable": None, 
                    "is_dhcp": None,
                    "is_rapidCommit": None,
                    "is_cga": None,
                    "is_eui": None,
                    "is_linkLocal": None,
                    "is_srDefault": None,
                    "is_srEnable": None,
                    "is_ipv6sr": None,
                    },):
    
    default_ipv4 = {
        "is_ipv4": False,
        "address": None,
        "mask": None,
        "is_secondIP": False,
        "is_dhcp": False,
        "client_id": None,
        "hostname": None,
    }
    default_ipv6 = {
    'is_ipv6': False,
    "address": None,
    "mask": None,
    "is_anycast": None,
    "is_autoconfigDefault": None,
    "is_autoconfigEnable": None,
    "is_dhcp": None,
    "is_rapidCommit": None,
    "is_cga": None,
    "is_eui": None,
    "is_linkLocal": None,
    "is_srDefault": None,
    "is_srEnable": None,
    "is_ipv6sr": None,
    }

    ipv4 = {**default_ipv4, **ipv4}
    ipv6 = {**default_ipv6, **ipv6}

    r = ansible_runner.run(private_data_dir=private_data_path,
                           playbook=rf'{playbookPath}set_l3interface.yml',
                           inventory=inventory_path,
                           quiet=True,
                           extravars=getAnsibleConfig({'hostname': hostname,
                                      'interface_name': interface,
                                      'ipv4': ipv4,
                                      'ipv6': ipv6,}))

    for event in r.events:
        event_data = event.get('event_data', {})
        if 'task' in event_data:
            task_name = event_data.get('task', 'Unnamed Task')
            task_action = event_data.get('task_action', 'no action')
            print(f"Task: {task_name}, Action: {task_action}")
            
            # Print out messages from tasks, if available
            if 'res' in event_data and 'msg' in event_data['res']:
                print(f"Message: {event_data['res']['msg']}")
## END ##