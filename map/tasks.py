from __future__ import absolute_import, unicode_literals

from celery import shared_task
import meraki
import requests
import ipaddress
from django.db import connection
from map.models import Site
from map.models import Device_Info, Client_Info, Org_Info, Employee, NetworkDevice,RunningConfig, NetworkInterface,NetworkTask,NetworkAccount, LdapAccount, FeatureRequest
from django.contrib.auth.models import User as AuthUser
from django.db import IntegrityError
from time import sleep
import subprocess
from subprocess import run, PIPE
import json
import os
from dotenv import load_dotenv
from dash.get_ip import get_system_ip
from dash.ansible_methods import run_ansible_playbook
from netutils.interface import abbreviated_interface_name
from dash.ansible_methods import run_ansible_playbook, ansible_logging, cleanup_artifacts_folder, update_host_file
from typing import Literal, Union, Optional
from dash.celery import app
import requests
from datetime import datetime, timedelta, timezone

# Define the base URL of the API
base_url = 'https://license.strawberryspider.com/api/'

# Define your secret token
secret_token = 'Bababooey'

github_token = os.getenv('GITHUB_TOKEN')

@app.task(queue='get_info_queue')
def check_date():
    org = Org_Info.objects.get()
    date = datetime.strptime(org.valid_time, '%Y-%m-%dT%H:%M:%SZ')
    current_time = datetime.now()
    if (current_time - date) > timedelta(days=7):
        org.license = ''
        org.valid = False
        org.save()
    else:
        print("Date has not passed by 7 days yet.")


@app.task(queue='configure_devices_queue')
def clean_artifacts():
    cleanup_artifacts_folder()

@app.task(queue='get_info_queue')
def github_pull_from_main():
    github_token = os.getenv('GITHUB_TOKEN')
    if github_token:
        # Ensure the GitHub access token is properly formatted
        github_token_url = f'x-access-token:{github_token}@'
        
        # Construct the URL for the git pull
        git_url = f'https://{github_token_url}github.com/StrawberrySpiderCo/Dash'
        
        # Perform git pull
        git_update = subprocess.run(['git', 'pull', git_url])
        
        # Perform database migration
        migrate_process = subprocess.run(['python3', 'manage.py', 'migrate'], cwd='/home/sbs/Dash', check=True)

@app.task(queue='ping_devices_queue')
def ping_devices_task():
    org_info = NetworkAccount.objects.get()
    network_ips = set(org_info.network_device_ips)
    
    for ip in network_ips:
        result = subprocess.call(['ping', ip, '-c', '2'])
        online = result == 0
        
        try:
            device = NetworkDevice.objects.get(ip_address=ip)
            
            if online and not device.online:
                device.online = True
                device.ansible_status = 'ONLINE'
                device.save()
                update_host_file()
            elif not online and device.online:
                device.online = False
                device.ansible_status = 'OFFLINE'
                device.save()
                update_host_file()
                
        except NetworkDevice.DoesNotExist:
            pass

@app.task(queue='configure_devices_queue')
def cycle_port_task(hostname, interface):
    r,output = run_ansible_playbook('cycle_port', {'hostname':hostname, 'ports_to_cycle': interface})
    events = r.events
    ansible_logging(events)

@app.task(queue='configure_devices_queue')
def update_port_info(hostname=None):

    if hostname is None:
        hostname = 'network_devices'
    r, output = run_ansible_playbook('get_interface_data',{'hostname':hostname})
    for runner_on_ok in output['runner_on_ok']:
        ip_address = (runner_on_ok['hostname'])
        net_device = NetworkDevice.objects.get(ip_address=ip_address)
        ansible_data = runner_on_ok['task_result']['ansible_facts']
        for interface_name, interface_data in ansible_data['ansible_net_interfaces'].items():
            short_name = abbreviated_interface_name(interface_name)
            defaults = {
                'device': net_device,
                'description': interface_data['description'],
                'mac_address': interface_data['macaddress'],
                'mtu': interface_data['mtu'],
                'bandwidth': interface_data['bandwidth'],
                'media_type': interface_data['mediatype'],
                'duplex': interface_data['duplex'],
                'line_protocol': interface_data['lineprotocol'],
                'oper_status': interface_data['operstatus'],
                'interface_type': interface_data['type'],
                'ipv4_address': interface_data['ipv4'][0]['address'] if interface_data['ipv4'] else None,
                'ipv4_subnet': interface_data['ipv4'][0]['subnet'] if interface_data['ipv4'] else None,
                'short_name': short_name
            }
            obj, created = NetworkInterface.objects.update_or_create(
                device=net_device,
                name=interface_name,
                defaults=defaults
            )

@app.task(queue='configure_devices_queue')
def set_interface(hostname: str,
            interface: Union[list, str],
            action: Literal['shut','noshut']):
    r,output = run_ansible_playbook('set_interfaceShut', {'hostname':hostname, 'interface_name': interface, 'input_action':action})
    events = r.events
    ansible_logging(events)
    update_port_info()

@app.task(queue='configure_devices_queue')
def set_l2interface(hostname, 
                interface, 
                mode, 
                vlan = 'None', 
                voice_vlan = 'None',
                native_vlan = 'None',
                allowed_vlan = 'None',
                encapsulation = 'dot1q'):
    r,output = run_ansible_playbook('set_l2interface', {'hostname':hostname, 'interface_name': interface, 'switchport_mode': mode, 'vlan_id': vlan, 'voice_vlan': voice_vlan, 'native_vlan': native_vlan, 'allowed_vlans': allowed_vlan,'encapsulation': encapsulation})
    events = r.events
    ansible_logging(events)
    update_port_info()

@app.task(queue='configure_devices_queue')
def set_l3interface(hostname: str = '',
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
    
    r,output = run_ansible_playbook('set_l3interface.yml',{'hostname': hostname,
                                      'interface_name': interface,
                                      'ipv4': ipv4,
                                      'ipv6': ipv6})

@app.task(queue='configure_devices_queue')
def push_startup_configs(hostname, config):
    ansible_events, ansible_results = run_ansible_playbook('push_startup_config', {'hostname': hostname, 'config': config})
    events = ansible_events.events
    ansible_logging(events)

@app.task(queue='configure_devices_queue')
def gather_startup_configs(hostname=None):
    if hostname is None:
        hostname = 'network_devices'
    ansible_events, ansible_results = run_ansible_playbook('get_startup_config', {'hostname': hostname})
    for runner_on_ok in ansible_results['runner_on_ok']:
        ip_address = (runner_on_ok['hostname'])
        stdout = ansible_results['runner_on_ok'][0]['task_result']['stdout']
        stdout_with_newlines = '\n'.join(stdout[0].split(', '))
        device = NetworkDevice.objects.get(ip_address=ip_address)
        device.startup_config = stdout_with_newlines
        device.save()
    events = ansible_events.events
    ansible_logging(events)

@app.task(queue='get_info_queue')
def gather_running_configs(hostname=None):
    if hostname is None:
        hostname = 'network_devices'
    ansible_events, ansible_results = run_ansible_playbook('get_running_config', {'hostname': hostname})
    for runner_on_ok in ansible_results['runner_on_ok']:
        ip_address = (runner_on_ok['hostname'])
        ansible_data = runner_on_ok['task_result']['ansible_facts']
        running_config = ansible_data['ansible_net_config']
        device = NetworkDevice.objects.get(ip_address=ip_address)
        RunningConfig.objects.create(
            device=device,
            config_text=running_config
        )
    for runner_on_failed in ansible_results['runner_on_failed']:
        ip_address = (runner_on_failed['hostname'])
        ansible_data = runner_on_failed['task_result']
        error_msg = ansible_data['msg']
    events = ansible_events.events
    ansible_logging(events)

@app.task(queue='get_info_queue')
def get_device_info(hostname=None):
    if hostname is None:
        hostname = 'network_devices'
    ansible_events, ansible_results = run_ansible_playbook('get_all',{'hostname':hostname})
    for runner_on_ok in ansible_results['runner_on_ok']:
        ip_address = (runner_on_ok['hostname'])
        ansible_data = runner_on_ok['task_result']['ansible_facts']
        hostname = ansible_data['ansible_net_hostname']
        model = ansible_data['ansible_net_model']
        firmware_version = ansible_data['ansible_net_version']
        serial_number = ansible_data['ansible_net_serialnum']
        image = ansible_data['ansible_net_image']
        net_device = NetworkDevice.objects.get(ip_address=ip_address)
        net_device.hostname = hostname
        net_device.model = model
        net_device.serial_number = serial_number
        net_device.firmware_version = firmware_version
        net_device.image = image
        net_device.ansible_status = 'runner_on_ok'
        net_device.save()
    for runner_on_failed in ansible_results['runner_on_failed']:
        ip_address = (runner_on_failed['hostname'])
        ansible_data = runner_on_failed['task_result']
        error_msg = ansible_data['msg']
        NetworkDevice.objects.update_or_create(
                    ip_address=ip_address,
                    defaults={
                        'ansible_status': error_msg
                    }
                )
    events = ansible_events.events
    ansible_logging(events)   

@app.task(queue='configure_devices_queue')
def update_host_file_task():
    update_host_file()

@app.task(queue='get_info_queue')
def setup_network_devices(added_ips=None, removed_ips=None):
    if added_ips is None and removed_ips is None:
        org_info = NetworkAccount.objects.get()
        network_ips = set(org_info.network_device_ips)
    else:
        # Update network devices based on added and removed IPs
        org_info = NetworkAccount.objects.get()
        network_ips = set(org_info.network_device_ips)

        if added_ips:
            network_ips.update(added_ips)

        if removed_ips:
            network_ips.difference_update(removed_ips)

        # Remove devices that are no longer in the list
        NetworkDevice.objects.exclude(ip_address__in=network_ips).delete()

    playbook_dir = '/home/sbs/Dash/ansible'
    host_file_path = f"{playbook_dir}/hosts.ini"
    if os.path.exists(host_file_path):
        os.remove(host_file_path)
    with open(host_file_path, 'w') as host_file:
        host_file.write("[network_devices]\n")
        for ip in network_ips:
            result = subprocess.call(['ping', ip, '-c', '2'])
            online = result == 0
            device, created = NetworkDevice.objects.update_or_create(
                ip_address=ip,
                defaults={
                    'model': '',
                    'username': org_info.ssh_username,
                    'password': org_info.ssh_password,
                    'enable_password': org_info.ssh_enable_password,
                    'online': online
                }
            )
            device.save()
            host_file.write(f"{ip} ansible_host={ip}\n")
        host_file.write("\n[network_devices:vars]\n")
        host_file.write("ansible_network_os=ios\n")
        host_file.write("ansible_connection=network_cli\n")

    get_device_info()
    update_port_info()
    gather_running_configs()
    gather_startup_configs()

@app.task(queue='configure_devices_queue')
def update_device(hostname):
    update_port_info(hostname)
    get_device_info(hostname)
    gather_startup_configs(hostname)
    gather_running_configs(hostname)

@app.task(queue='api_queue')
def setup_github_repo():
    # Retrieve Org_Info instance
    org_info = Org_Info.objects.get()
    
    print(github_token)
    
    if github_token:
        github_pull_from_main()
        repo_name = org_info.org_name.lower().replace(" ", "-")
        org_info.repo_name = f"{repo_name}-dash"
        org_info.save()
        headers = {'Authorization': f'token {github_token}'}
        payload = {
            'name': repo_name+'-dash',
            'private': True 
        }
        response = requests.post(
            'https://api.github.com/user/repos',
            json=payload,
            headers=headers
        )
        if response.status_code != 201:
            return f"Failed to create repository on GitHub: {response.text}"
        
        new_repo_url = f'https://github.com/StrawberrySpiderCo/{repo_name}-dash.git'
        # Change the remote URL
        remote_change = subprocess.run(['git', 'remote', 'set-url', 'origin', new_repo_url])
        if remote_change.returncode != 0:
            return "Failed to change remote URL."

        # Rename the default branch to 'main'
        branch_rename = subprocess.run(['git', 'branch', '-M', 'main'])
        if branch_rename.returncode != 0:
            return "Failed to rename the default branch to 'main'."

        # Push changes to the new repository
        push_changes = subprocess.run(['git', 'push', '-u', f'https://x-access-token:{github_token}@github.com/StrawberrySpiderCo/{repo_name}-dash.git', 'main'])
        if push_changes.returncode != 0:
            return "Failed to push changes to the new repository."
        server_ip = get_system_ip()
        # Write setup info to a file
        file_path = os.path.join('/home/sbs/Dash/dash', 'setup_info.txt')
        with open(file_path, 'w') as file:
            file.write(f"Org Name: {org_info.org_name}\n")
            file.write(f"Website IP: {server_ip}\n")
            file.write(f"Site Count: {org_info.site_count}\n")
            file.write(f"Contact Email: {org_info.contact_email}\n")
            file.write(f"Contact Phone: {org_info.contact_phone}\n")
        
        # Add, commit, and push the file to the repository
        add_file = subprocess.run(['git', 'add', 'dash/setup_info.txt'])
        if add_file.returncode != 0:
            return "Failed to add the file to the Git repository."

        commit_changes = subprocess.run(['git', 'commit', '-m', 'Add setup info file'])
        if commit_changes.returncode != 0:
            return "Failed to commit the changes."

        push_changes = subprocess.run(['git', 'push'])
        if push_changes.returncode != 0:
            return "Failed to push changes to the remote repository."

        return "Setup completed successfully."
    else:
        return "GitHub credentials not configured properly"
    
@app.task(queue='api_queue')
def create_org_api():
    org = Org_Info.objects.get()
    org_data = {
    'name': org.org_name,
    'repo_name': org.repo_name,
    'contact_email': org.contact_email,
    'contact_phone': org.contact_phone,
    'hamster_solar': secret_token,  
}
    response = requests.post(base_url + 'create/org/', data=org_data)
    if response.status_code == 200:
        org_id = response.json()['org_id']
        org.org_id = org_id
        org.save()
    else:
        return('Failed to create organization')



@app.task(queue='configure_devices_queue')
def sync_ldap():
    try:
        LdapAccount.objects.get()
        subprocess.run(['python3', 'manage.py', 'sync_ldap'], cwd='/home/sbs/Dash')
    except:
        pass
    
@shared_task
def clean_up():
    RunningConfig.objects.all().delete()
    NetworkTask.objects.all().delete()
def nuke():
    RunningConfig.objects.all().delete()
    NetworkTask.objects.all().delete()
    AuthUser.objects.all().delete()
    Org_Info.objects.all().delete()
    NetworkDevice.objects.all().delete()
    NetworkInterface.objects.all().delete()
    NetworkAccount.objects.all().delete()
    LdapAccount.objects.all().delete()
    FeatureRequest.objects.all().delete()
### MERAKI, AZURE, WEBEX CODE #####
'''
@shared_task
def update_vlan_info_task():
    api_key = '16209be12e5a4e06b76e0a6d668c5477b20924d9'
    headers = {
        'X-Cisco-Meraki-API-Key': api_key,
        'Content-Type': 'application/json',
    }
    base_url = 'https://api.meraki.com/api/v1'
    sites = Site.objects.all()
    site_count = len(sites) 
    total_clients = 0
    for sited in sites:
        network_id = sited.networkId
        res = requests.get(f"{base_url}/networks/{network_id}/clients?statuses[]=Online&perPage=1000", headers=headers)
        clients = res.json() if res.status_code == 200 else []
        if clients:
            for client in clients:
                total_clients += 1
                try:
                    existing_client = Client_Info.objects.get(mac=str(client['mac']))
                except Client_Info.DoesNotExist:
                    try:
                        existing_client = Client_Info.objects.get(ip=str(client['ip']))
                    except Client_Info.DoesNotExist:
                        Client_Info.objects.create(
                        mac = str(client['mac']),
                        network_name = str(sited.name),
                        client_id = str(client['id']),
                        description = str(client['description']),
                        ip = str(client['ip']),
                        ip6 = str(client['ip6']),
                        ip6Local = str(client['ip6Local']),
                        user = str(client['user']),
                        firstSeen = str(client['firstSeen']),
                        lastSeen = str(client['lastSeen']),
                        manufacturer = str(client['manufacturer']),
                        os = str(client['os']),
                        deviceTypePrediction = str(client['deviceTypePrediction']),
                        recentDeviceSerial = str(client['recentDeviceSerial']),
                        recentDeviceName = str(client['recentDeviceName']),
                        recentDeviceMac = str(client['recentDeviceMac']),
                        recentDeviceConnection = str(client['recentDeviceConnection']),
                        ssid = str(client['ssid']),
                        vlan = str(client['vlan']),
                        switchport = str(client['switchport']),
                        usage = client['usage'],
                        status = str(client['status']),
                        notes = str(client['notes']),
                        groupPolicy8021x = str(client['groupPolicy8021x']),
                        adaptivePolicyGroup = str(client['adaptivePolicyGroup']),
                        smInstalled = str(client['smInstalled']),
                        pskGroup = str(client['pskGroup']),
                    )
        resp = requests.get(f"{base_url}/networks/{network_id}/appliance/vlans", headers=headers)
        vlans = resp.json() if resp.status_code == 200 else []
        available_ips = {} 
        info = {} 
        for vlan in vlans:
            subnet = vlan['subnet']
            subnet_info = ipaddress.IPv4Network(subnet)
            all_ips = [str(ip) for ip in subnet_info.hosts()]
            
            client_ip = [client['ip'] for client in clients]
            available_ips[vlan['name']] = [ip for ip in all_ips if ip not in client_ip]
            used_count = len(all_ips) - len(available_ips[vlan['name']])
            percentage_used = (used_count / len(all_ips)) * 100
            subnet_used_percentage = round(percentage_used, 2)
            
            info[vlan['name']] = {
                "available_ips": available_ips[vlan['name']],
                "sub_percent": subnet_used_percentage
            }

        sited.vlans = vlans
        sited.clients = clients
        sited.available = info
        sited.save()
    org = Org_Info.objects.get(pk = 1)
    org.client_count = total_clients
    org.site_count = site_count
    org.save()
@shared_task
def update_device_info_task():
    sites = Site.objects.all()
    api_key = '16209be12e5a4e06b76e0a6d668c5477b20924d9'
    base_url = 'https://api.meraki.com/api/v1'
    session_params = {
        'api_key': api_key,
        'single_request_timeout': 30,
        'base_url': base_url,
        'certificate_path': None,
        'requests_proxy': None,
        'wait_on_rate_limit': True,
        'nginx_429_retry_wait_time': 1,
        'action_batch_retry_wait_time': 1,
        'retry_4xx_error': True,
        'retry_4xx_error_wait_time': 1,
        'maximum_retries': 100,
        'simulate': False,
        'be_geo_id': None,
        'caller': None,
        'use_iterator_for_get_pages': False
    }
    dashboard = meraki.DashboardAPI(**session_params)
    organization_id = '445912'
    networks = dashboard.organizations.getOrganizationNetworks(organization_id)
    network_dict = {}
    network_blacklist = ['Spare Network', 'MDM Executive Mobile', 'MDM Executive Laptop', 'MDM Line Staff Mobile', 'Azure KC Hub', 'Azure Test', 'MDM IT Test']
    for network in networks:
        if network['name'] in network_blacklist:
            del network['name']
        else:
            network_add = {network['id']: network['name']}
            network_dict.update(network_add)                                                                                                                                                                 
    response = requests.get(f"{base_url}/organizations/{organization_id}/devices", headers={'Authorization': f'Bearer {api_key}'})
    network_devices = response.json()
    for device in network_devices:
        if device['networkId'] in network_dict:
            device_network = {"networkName":network_dict.get(device['networkId'])}
            if device['model'].startswith("MX"):
                try:
                    site = Site.objects.get(networkId = device['networkId'])
                    site.router_sn = device['serial']
                    site.save()
                except:
                    print()
            device.update(device_network)
            Device_Info.objects.update_or_create(
                serial=device['serial'],
                defaults={
                    'mac': device['mac'],
                    'url': device['url'],
                    'networkId': device['networkId'],
                    'name': device['name'],
                    'model': device['model'],
                    'firmware': device['firmware'],
                    'productType': device['productType'],
                    'networkName': device['networkName']
                }
            )
@shared_task
def get_user_list():
    get_user_url = "https://graph.microsoft.com/v1.0/groups/fe10e5e7-cdb6-43e9-ad31-7a7798ce4532/members"
    fresno_get_user = "https://graph.microsoft.com/v1.0/groups/2748aeb0-f949-48bb-b9db-5006b7ae820f/members"
    tenant_id = '370fb7ee-e5b0-4bf5-b91b-3b67fe429a27'
    client_id = 'dae1f98c-134e-4f18-ba76-bbe8223da261'
    client_secret = 'itG8Q~_0x64VGLU5t_jon0rtesAJCUP~jgmOQav4'
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }

    response = requests.post(token_url, data=token_data)
    response.raise_for_status()
    access_token = response.json()['access_token']
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'ConsistencyLevel':'eventual'
    }
    surname_count = {}
    user_count = 0
    url = get_user_url
    url1 = fresno_get_user

    while url:
        info = requests.get(url, headers=headers)
        info.raise_for_status()
        user_data = info.json()
        for user in user_data['value']:
             Employee.objects.update_or_create(display_name = user['displayName'], azure_id = user['id'], first_name = user['givenName'], phone = user['businessPhones'], last_name = user['surname'], title = user['jobTitle'], mail = user['mail'])
             url = user_data.get('@odata.nextLink')
    while url1:
        info = requests.get(url1, headers=headers)
        info.raise_for_status()
        user_data = info.json()
        for user in user_data['value']:
            Employee.objects.update_or_create(display_name = user['displayName'], azure_id = user['id'], first_name = user['givenName'], phone = user['businessPhones'], last_name = user['surname'], title = user['jobTitle'], mail = user['mail'])
            url1 = user_data.get('@odata.nextLink')
@shared_task
def get_user_info():
    tenant_id = '370fb7ee-e5b0-4bf5-b91b-3b67fe429a27'
    client_id = 'dae1f98c-134e-4f18-ba76-bbe8223da261'
    client_secret = 'itG8Q~_0x64VGLU5t_jon0rtesAJCUP~jgmOQav4'
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }

    response = requests.post(token_url, data=token_data)
    response.raise_for_status()
    access_token = response.json()['access_token']
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'ConsistencyLevel':'eventual'
    }

    employees = Employee.objects.all()
    for employee in employees:
        if not employee.upn:
            get_user_url = f"https://graph.microsoft.com/v1.0/users/{employee.azure_id}"
            request = requests.get(get_user_url, headers=headers)
            data_request = request.json()
            employee.upn = data_request['userPrincipalName']
            employee.save()
@shared_task
def clean_up():
    from django.db.models import Max

    def reset_sequence(model):
        max_id = model.objects.all().aggregate(max_id=Max('id'))['max_id']
        if max_id is not None:
            with connection.cursor() as cursor:
                cursor.execute(f'ALTER SEQUENCE {model._meta.db_table}_id_seq RESTART WITH {max_id + 1}')

    reset_sequence(Client_Info)
    reset_sequence(Device_Info)

    Client_Info.objects.all().delete()
    Device_Info.objects.all().delete()
@shared_task
def get_webex_id():
    webex_all_people = 'https://webexapis.com/v1/people?callingData=false&max=1000'
    with open('map\\webex_access.txt', 'r') as access:
        access_token = access.read()
    headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
    people_request = requests.get(webex_all_people,headers=headers)
    people_request.raise_for_status()
    people = people_request.json()
    for person in people['items']:
            email = person['emails']
            mail = email[0]
            try:
                user = Employee.objects.get(upn = mail)
                user.webex_id = person['id']
                print(f"{user.display_name} has an id {user.webex_id}")
                user.save()
            except Employee.DoesNotExist:   
                pass
    if 'Link' in people_request.headers and 'rel="next"' in people_request.headers['Link']:
        next_url = people_request.headers['Link'].split(';')[0][1:-1]
        people_request = requests.get(next_url, headers=headers)
        people_request.raise_for_status()
        people = people_request.json()
        for person in people['items']:
            email = person['emails']
            mail = email[0]
            try:
                user = Employee.objects.get(upn = mail)
                user.webex_id = person['id']
                print(f"{user.display_name} has an id {user.webex_id}")
                user.save()
            except Employee.DoesNotExist:   
                pass
    if 'Link' in people_request.headers and 'rel="next"' in people_request.headers['Link']:
        next_url = people_request.headers['Link'].split(';')[0][1:-1]
        people_request = requests.get(next_url, headers=headers)
        people_request.raise_for_status()
        people = people_request.json()
        for person in people['items']:
            email = person['emails']
            mail = email[0]
            try:
                user = Employee.objects.get(upn = mail)
                user.webex_id = person['id']
                print(f"{user.display_name} has an id {user.webex_id}")
                user.save()
            except Employee.DoesNotExist:   
                pass
@shared_task
def get_webex_info():
    webex_person = "https://webexapis.com/v1/people/"
    employees = Employee.objects.all()
    with open('map\\webex_access.txt', 'r') as access:
        access_token = access.read()
    headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
    for employee in employees:
        if not employee.extension and employee.webex_id:
            person_request = requests.get(webex_person+employee.webex_id,headers=headers)
            person_request.raise_for_status()
            person_info=person_request.json()                         
            extension = None
            if person_info.get('phoneNumbers'):
                for number in person_info.get('phoneNumbers'):
                    if number.get("type") == "work_extension":
                        extension = number.get("value")
                        break
            employee.extension = extension
            employee.webex_lic = person_info.get('licenses')
            employee.save()
@shared_task
def delete_dev_id():
    employees = Employee.objects.all()
    for employee in employees:
        employee.webex_dev_id = None
        employee.save()
@shared_task
def get_webex_dev_id():
    employees = Employee.objects.all()
    webex_devices = "https://webexapis.com/v1/devices?personId="
    with open('map\\webex_access.txt', 'r') as access:
        access_token = access.read()
    headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
    for employee in employees:
        if not employee.site and employee.webex_id:
            sleep(.8)
            url = f"{webex_devices}{employee.webex_id}"
            device_info = requests.get(url, headers=headers)
            devicejson = device_info.json()
            if devicejson['items']:
                for device in devicejson['items']:
                    if device['type'] ==  'phone':
                        dev_id = device['id']
                        mac = device['mac']
                        employee.webex_dev_id = dev_id
                        employee.phone_mac = mac
                        employee.webex_model = device['product']
                        if device['locationId']:
                            employee.webex_loc_id = device['locationId']
                            location = Site.objects.get(webex_id = device['locationId'])
                            employee.site = location.name
                        print(f"{employee.display_name}  {employee.site}")
                employee.save()
                #print(f"{employee.display_name}  {employee.webex_model}")
        else:
            pass
            #print(f"DID NOT RUN LOOP INFO MAY EXSIT ALREADY {employee.display_name}   {employee.site}")
@shared_task
def get_location_webex_id():
    locations_url = 'https://webexapis.com/v1/locations'
    with open('map\\webex_access.txt', 'r') as access:
        access_token = access.read()
    headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
    location_request = requests.get(locations_url, headers=headers)
    location_info = location_request.json()
    for location in location_info['items']:
            try:
                site = Site.objects.get(webexName = location['name'])
                site.webex_id = location['id']
                site.save()
            except Site.DoesNotExist:   
                pass
@shared_task
def get_webex_token():
    token_url = 'https://webexapis.com/v1/access_token'
    client_secret = '0ff9659e9f14bccbdd41397ddcd37e5f074e68056bd730d5adf5cb892a5b1efa'
    client_id  = 'C8010c7a4696232bb5444df72cc05808713d60b398cb10dbfbfe13ea8e68b25ec'
    with open('map\\webex_refresh.txt', 'r') as refresh:
        refresh_token = refresh.read()
    refresh_payload = {
        'client_id':client_id,
        'client_secret':client_secret,
        'refresh_token':refresh_token,
        'grant_type':"refresh_token", 
    }
    refresh = requests.post(token_url,data=refresh_payload)
    refresh_info = (refresh.json())
    refresh_token = (refresh_info['refresh_token'])
    access_token = (refresh_info['access_token'])
    with open('map\\webex_access.txt', 'w') as env_file:
        env_file.write(f'{access_token}')
    with open('map\\webex_refresh.txt','w') as refreshtxt:
        refreshtxt.write(f'{refresh_token}')

        '''