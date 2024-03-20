from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect
from IPy import IP
from django import forms
import re
from json import loads
import netmiko
import ipaddress
from netmiko import ConnectHandler
import django.contrib.staticfiles 
import difflib
import paramiko
import subprocess
from django.contrib.staticfiles.views import serve
import logging
from map.models import Site
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
import meraki
import requests
import aiohttp
import asyncio
from asgiref.sync import async_to_sync, sync_to_async
from django.contrib.auth.decorators import login_required
from map.models import Device_Info, Client_Info, Org_Info
from concurrent.futures import ThreadPoolExecutor
from map.tasks import update_vlan_info_task, update_device_info_task, setup_github_repo, setup_network_devices
from time import sleep
import json
import os
import csv
from django.contrib.auth.decorators import user_passes_test
from .models import FeatureRequest
from django.core.exceptions import ValidationError

def user_is_admin(user):
    return user.groups.filter(name='Admins').exists()

class IpForm(forms.Form):
    router_ip = forms.CharField(label='Router IP address', max_length=15)
    
from .forms import OrgInfoForm, AdminCreationForm
from django.contrib.auth.models import User

def setup(request):
    if Org_Info.objects.exists():
        return redirect('home')
    
    if request.method == 'POST':
        org_form = OrgInfoForm(request.POST, request.FILES)
        admin_form = AdminCreationForm(request.POST)
        
        if org_form.is_valid() and admin_form.is_valid():
            org_info = org_form.save(commit=False)
            try:
                username = admin_form.cleaned_data['username']
                password = admin_form.cleaned_data['password1']
                email = org_form.cleaned_data['contact_email']
                csv_file = org_form.cleaned_data.get('csv_file')
                
                # Process CSV file if provided
                if csv_file:
                    try:
                        ips = []
                        reader = csv.reader(csv_file)
                        for row in reader:
                            ips.extend(row)
                        org_info.network_device_ips = ips
                    except Exception as e:
                        print(e)
                        pass
                else:
                    network_device_ips = org_form.cleaned_data.get('network_device_ips', [])
                    org_info.network_device_ips = network_device_ips
                org_info.save()
                setup_github_repo.delay(org_info.id)
                setup_network_devices.delay(org_info.id)
                user = User.objects.create_user(username, email=email, password=password)
                user.is_superuser = True
                user.is_staff = True
                user.save()
                return redirect('success_setup')
            except ValidationError as e:
                error_message = str(e)
                return render(request, 'setup.html', {'error_message': error_message})
    
    else:
        org_form = OrgInfoForm()
        admin_form = AdminCreationForm()
    
    return render(request, 'setup.html', {'org_form': org_form, 'admin_form': admin_form})

def success_setup(request):
    org_info = Org_Info.objects.get()  # Retrieve the single Org_Info object
    return render(request, 'success_setup.html', {'org_info': org_info})

@login_required
def getConfigDiff(request):
    if request.method == 'POST':
        form = IpForm(request.POST)
        if form.is_valid():
            router_ip = form.cleaned_data['router_ip']
            username = 'so_tomlinj'
            password = 'Password123$'
            ssh = paramiko.SSHClient()
            device = {
                'device_type': 'cisco_ios',
                'ip': router_ip,
                'username': username,
                'password': password,
            }
            try:
                ssh = ConnectHandler(**device)
                running_config = ssh.send_command('show running-config | begin hostname')
                startup_config = ssh.send_command('show startup-config | begin hostname')
                ssh.disconnect()
                config_diff = list(difflib.unified_diff(startup_config.splitlines(), running_config.splitlines(), fromfile='startup-config', tofile='running-config', lineterm=''))
                return render(request, 'getConfigDiff.html', {'config_diff': config_diff})
            except:
                error_msg = 'Failed to connect to router. Please check the router IP, username, and password.'
                return render(request, 'getConfigDiff.html', {'error_msg': error_msg})
        else:
            return JsonResponse({'error': 'Invalid form'})
    else:
        form = IpForm()
        return render(request, 'getConfigDiff.html', {'form': form})
@login_required   
def ping_view(request):
    if request.method == 'POST':
        form = IpForm(request.POST)
        if form.is_valid():
            router_ip = form.cleaned_data['router_ip']
            name = form.data['marker_name']
            # Run the ping command and capture the output
            result = subprocess.call(['ping',  router_ip, '-n', '1', '-w', '100'])
            # Get the output and return it to the user
            # Check if the ping was successful
            if result == 1:
                html = 'Ping Failed'
            elif result == 0:
                html = "Ping was successful"
            else:
                html = ''
    # Return the HTML content as a string to be displayed in the alert box
    return render(request, 'map.html',{'html': html, 'name':name})
@login_required
def site_details(request, site_id):
    site = get_object_or_404(Site, pk=site_id)
    return render(request, 'site_details.html', {'site': site})
@login_required
def device_details(request, device_id):
    device = get_object_or_404(Device_Info, pk=device_id)
    return render(request, 'device_details.html', {'device': device})
@login_required
def map_view(request):
    sites = Site.objects.all()
    return render(request, 'map.html', {'sites': sites})
@login_required
def wikis_view(request):
    return render(request, 'wikis.html')
@login_required
def home_view(request):
    return render(request, 'home.html')
@login_required
def purrception_view(request):
    org = get_object_or_404(Org_Info, pk=1)
    return render(request, 'purrception.html', {'org': org})

@login_required
def purrception_results(request):
    output_messages = []
    if request.method == 'POST':
        address = request.POST.get('address')
        try:
            (IP(address))
            try:
                device = get_object_or_404(Client_Info, ip=address)
                all_fields_data = {
                'client_id': device.client_id,
                'mac': device.mac,
                'site_name': device.network_name,
                'description': device.description,
                'ip': device.ip,
                'ip6': device.ip6,
                'ip6Local': device.ip6Local,
                'user': device.user,
                'firstSeen': device.firstSeen,
                'lastSeen': device.lastSeen,
                'manufacturer': device.manufacturer,
                'os': device.os,
                'deviceTypePrediction': device.deviceTypePrediction,
                'recentDeviceSerial': device.recentDeviceSerial,
                'recentDeviceName': device.recentDeviceName,
                'recentDeviceMac': device.recentDeviceMac,
                'recentDeviceConnection': device.recentDeviceConnection,
                'ssid': device.ssid,
                'vlan': device.vlan,
                'switchport': device.switchport,
                'usage': device.usage,
                'status': device.status,
                'notes': device.notes,
                'groupPolicy8021x': device.groupPolicy8021x,
                'adaptivePolicyGroup': device.adaptivePolicyGroup,
                'smInstalled': device.smInstalled,
                'pskGroup': device.pskGroup,
                
            }
                output_messages.append(all_fields_data)
            except:
                output_messages.append({'error': (f"No Devices found that match ({address})")})
        except:
            try:
                mac = address
                mac = re.sub('[.:-]', '', mac).lower()  # remove delimiters and convert to lower case
                mac = ''.join(mac.split())  # remove whitespaces
                assert len(mac) == 12  # length should be now exactly 12 (eg. 008041aefd7e)
                assert mac.isalnum()  # should only contain letters and numbers
                # convert mac in canonical form (eg. 00:80:41:ae:fd:7e)
                mac = ":".join(["%s" % (mac[i:i+2]) for i in range(0, 12, 2)])
                device = get_object_or_404(Client_Info, mac=mac)
                all_fields_data = {
                    'client_id': device.client_id,
                'mac': device.mac,
                'site_name': device.network_name,
                'description': device.description,
                'ip': device.ip,
                'ip6': device.ip6,
                'ip6Local': device.ip6Local,
                'user': device.user,
                'firstSeen': device.firstSeen,
                'lastSeen': device.lastSeen,
                'manufacturer': device.manufacturer,
                'os': device.os,
                'deviceTypePrediction': device.deviceTypePrediction,
                'recentDeviceSerial': device.recentDeviceSerial,
                'recentDeviceName': device.recentDeviceName,
                'recentDeviceMac': device.recentDeviceMac,
                'recentDeviceConnection': device.recentDeviceConnection,
                'ssid': device.ssid,
                'vlan': device.vlan,
                'switchport': device.switchport,
                'usage': device.usage,
                'status': device.status,
                'notes': device.notes,
                'groupPolicy8021x': device.groupPolicy8021x,
                'adaptivePolicyGroup': device.adaptivePolicyGroup,
                'smInstalled': device.smInstalled,
                'pskGroup': device.pskGroup,
            }
                output_messages.append(all_fields_data)
            except:
                output_messages.append({'error': (f"No Devices found that match ({address})")})

         
    return render(request, 'purrception_results.html', {'output_messages': output_messages})
@login_required
def tools_view(request):
    return render(request, 'tools.html')
@login_required
def projects_view(request):
    return render(request, 'projects.html')

@login_required
def ipam_view(request):
    sites = Site.objects.all()
    return render(request, 'ipam.html', {'sites': sites})

@login_required
@user_passes_test(user_is_admin, login_url='invalid_login')
def update_vlan_info(request):
    update_vlan_info_task.delay()
    return redirect('ipam')

@user_passes_test(user_is_admin, login_url='invalid_login')
def multiplicity_view(request):
    sites = Site.objects.all()
    return render(request, 'multiplicity.html', {'sites': sites})

@user_passes_test(user_is_admin, login_url='invalid_login')
def rule_cloner_view(request):
    sites = Site.objects.all()
    return render(request, 'rule_clone.html', {'sites': sites})

@user_passes_test(user_is_admin, login_url='invalid_login')
def wireless_bomber_view(request):
    return render(request, 'wifi_bomber.html')

def microsoft_webhook(request):
    if 'validationToken' in request.GET:
        validation_token = request.GET['validationToken']
        return HttpResponse(validation_token, content_type='text/plain')
    else:
        return HttpResponse(status=400)

@user_passes_test(user_is_admin, login_url='invalid_login')
def wireless_bomber_execution_view(request):
    output_messages = []
    api_key = '16209be12e5a4e06b76e0a6d668c5477b20924d9'
    base_url = 'https://api.meraki.com/api/v1'
    session_params = {
    'api_key': api_key,
    'base_url': base_url,

}
    dashboard = meraki.DashboardAPI(**session_params)
    headers = {
        'X-Cisco-Meraki-API-Key': api_key,
        'Content-Type': 'application/json',
    }

    organization_id = '445912'
    networks = dashboard.organizations.getOrganizationNetworks(organization_id)


    for network in networks:
        network_id = network['id']
        response = requests.get(f"https://api.meraki.com/api/v1/networks/{network_id}/wireless/ssids", headers=headers)
        if response.status_code == 200:
            ssids = response.json()
            for ssid in ssids:
                if ssid['name'] == "CSV Wireless":
                    ssid_num = ssid['number']
            if ssid_num >= 0: 
                ssid_get = requests.get(f"https://api.meraki.com/api/v1/networks/{network_id}/wireless/ssids/{ssid_num}", headers=headers)
                if ssid_get.status_code == 200:
                    output_messages.append(f"Found CSV Wireless at {network['name']}")
                    ssid_info = ssid_get.json()
                    ssid_info['enabled'] = False
                    ssid_put = requests.put(f"https://api.meraki.com/api/v1/networks/{network_id}/wireless/ssids/{ssid_num}", headers=headers, json=ssid_info)
                    if ssid_put.status_code == 200:
                        output_messages.append(f"CSV Wireless Successfully Removed from {network['name']}")
                    else: 
                        output_messages.append(f"Error Removing CSV Wireless - {ssid_put.text}")
            else:
                output_messages.append(f"Could not find CSV Wireless on {network['name']}")

    return render(request, 'wireless_bomber_results.html', {'output_messages': output_messages})

@user_passes_test(user_is_admin, login_url='invalid_login')
def rule_cloner(request):
    sites = Site.objects.all()
    output_messages = []
    if request.method == 'POST':
        selected_sites = request.POST.getlist('selected_sites')
        address1 = request.POST.get('address1')
        address2 = request.POST.get('address2')
    api_key = '16209be12e5a4e06b76e0a6d668c5477b20924d9'
    headers = {
        'X-Cisco-Meraki-API-Key': api_key,
        'Content-Type': 'application/json',
    }
    site_list = json.loads(selected_sites[0])
    for site in site_list:
        output_messages.append(site)
        sited = Site.objects.get(name = site)
        serial = sited.router_sn
        res = requests.get(f"https://api.meraki.com/api/v1/devices/{serial}/appliance/uplinks/settings", headers=headers)
        if res.status_code == 200:
            output_messages.append("Successfully retreived uplink information")
            ints = res.json()


            new_nameservers = [address1, address2]

            try:
             # Updating the nameservers for both 'wan1' and 'wan2' interfaces
                ints['interfaces']['wan1']['svis']['ipv4']['nameservers']['addresses'] = new_nameservers
                ints['interfaces']['wan2']['svis']['ipv4']['nameservers']['addresses'] = new_nameservers
            except:
                output_messages.append("Could not change DNS settings")

            updated_json = json.dumps(ints)

            # Update the uplink settings
            response = requests.put(f"https://api.meraki.com/api/v1/devices/{serial}/appliance/uplinks/settings", headers=headers, data=updated_json)

            # Handle the response
            if response.status_code == 200:
                output_messages.append("Uplink settings updated successfully")
            else:
                output_messages.append("Failed to update uplink settings")
                output_messages.append(response.text)


    return render(request, 'clone_results.html',  {'output_messages': output_messages, 'site': site})
@user_passes_test(user_is_admin, login_url='invalid_login')
def clone_rf(request):
    output_messages = []
    if request.method == 'POST':
        selected_sites = request.POST.getlist('selected_sites')
        band_selection_type = request.POST.get('band_selection_type')
        min_bitrate_type = request.POST.get('min_bitrate_type')
        name = request.POST.get('profile_name')
        steer_client = request.POST.get('steer_client')
        client_balancing = request.POST.get('client_balancing')
        ap_band_mode = request.POST.get('ap_band_mode')
        ap_steer_client = request.POST.get('ap_steer_client')
        two_four_ghz_max_power = request.POST.get('two_four_ghz_max_power')
        two_four_ghz_min_power = request.POST.get('two_four_ghz_min_power')
        two_four_ghz_rx_sop = request.POST.get('two_four_ghz_rx_sop')
        two_four_ghz_ax_enabled = request.POST.get('two_four_ghz_ax_enabled')
        two_four_ghz_min_bitrate = request.POST.get('two_four_ghz_min_bitrate')
        five_ghz_max_power = request.POST.get('five_ghz_max_power')
        five_ghz_min_bitrate = request.POST.get('five_ghz_min_bitrate')
        five_ghz_min_power = request.POST.get('five_ghz_min_power')
        five_ghz_rx_sop = request.POST.get('five_ghz_rx_sop')
        six_ghz_max_power = request.POST.get('six_ghz_max_power')
        six_ghz_min_bitrate = request.POST.get('six_ghz_min_bitrate')
        six_ghz_min_power = request.POST.get('six_ghz_min_power')
        six_ghz_rx_sop = request.POST.get('six_ghz_rx_sop')
        flex_radios_by_model = request.POST.get('flex_radios_by_model')
        ssid_0_mode = request.POST.get('ssid_0_mode')
        ssid_0_steer_client = request.POST.get('ssid_0_steer_client')
        ssid_0_min_bitrate = request.POST.get('ssid_0_min_bitrate')
        ssid_1_mode = request.POST.get('ssid_1_mode')
        ssid_1_steer_client = request.POST.get('ssid_1_steer_client')
        ssid_1_min_bitrate = request.POST.get('ssid_1_min_bitrate')
        ssid_2_mode = request.POST.get('ssid_2_mode')
        ssid_2_steer_client = request.POST.get('ssid_2_steer_client')
        ssid_2_min_bitrate = request.POST.get('ssid_2_min_bitrate')


    # Replace 'YOUR_MERAKI_API_KEY' and 'YOUR_NETWORK_ID' with appropriate values
    api_key = '16209be12e5a4e06b76e0a6d668c5477b20924d9'
    headers = {
        'X-Cisco-Meraki-API-Key': api_key,
        'Content-Type': 'application/json',
    }
    site_list = json.loads(selected_sites[0])

    
    for site in site_list:
        output_messages.append(site)
        sited = Site.objects.get(name = site)
        network_id = sited.networkId
        res = requests.get(f"https://api.meraki.com/api/v1/networks/{network_id}/wireless/ssids", headers=headers)
        if res.status_code == 200:
            ssids = res.json()
            for ssid in ssids:
                if ssid['name'] == "CSV Wireless":
                    wireless = ssid['number']
                elif ssid['name'] == "CSV Guest":
                    guest = ssid['number']
                elif ssid['name'] == "CSV IOT":
                    iot = ssid['number']
                else:
                    if ssid['enabled'] == True:
                        dis_list = {
                            "enabled": False
                        }
                        rem = requests.put(f"https://api.meraki.com/api/v1/networks/{network_id}/wireless/ssids/{ssid['number']}", headers=headers, json=dis_list)
                        if rem.status_code == 200:
                            output_messages.append(f"Disabled {ssid['name']}")
                        else:
                            output_messages.append(f"No SSIDs disabled")
            if "WIC" or "BH" or "Dental" in sited.name:
                rf_profile_data = {
            "name": name,
            "bandSelectionType": band_selection_type,
            "minBitrateType": min_bitrate_type,
            "steerClient": steer_client,
            "clientBalancing": client_balancing,
            "apBandMode": ap_band_mode,
            "apSteerClient": ap_steer_client,
            "twoFourGhzSettings": {
                "maxPower": int(two_four_ghz_max_power),
                "minPower": int(two_four_ghz_min_power),
                "rxSop": two_four_ghz_rx_sop,
                "axEnabled": two_four_ghz_ax_enabled,
                "minBitrate": float(two_four_ghz_min_bitrate),
            },
            "fiveGhzSettings": {
                "maxPower": int(five_ghz_max_power),
                "minBitrate": int(five_ghz_min_bitrate),
                "minPower": int(five_ghz_min_power),
                "rxSop": five_ghz_rx_sop,

            },
            "flexRadiosByModel": flex_radios_by_model,
            "perSsidSettings": {
                wireless: {
                    "bandOperationMode": ssid_0_mode,
                    "bandSteeringEnabled": ssid_0_steer_client,
                },
                guest: {
                    "bandOperationMode": ssid_1_mode,
                    "bandSteeringEnabled": ssid_1_steer_client,
                },
            },
    }   
            else:
                rf_profile_data = {
            "name": name,
            "bandSelectionType": band_selection_type,
            "minBitrateType": min_bitrate_type,
            "steerClient": steer_client,
            "clientBalancing": client_balancing,
            "apBandMode": ap_band_mode,
            "apSteerClient": ap_steer_client,
            "twoFourGhzSettings": {
                "maxPower": int(two_four_ghz_max_power),
                "minPower": int(two_four_ghz_min_power),
                "rxSop": two_four_ghz_rx_sop,
                "axEnabled": two_four_ghz_ax_enabled,
                "minBitrate": float(two_four_ghz_min_bitrate),
            },
            "fiveGhzSettings": {
                "maxPower": int(five_ghz_max_power),
                "minBitrate": int(five_ghz_min_bitrate),
                "minPower": int(five_ghz_min_power),
                "rxSop": five_ghz_rx_sop,

            },
            "flexRadiosByModel": flex_radios_by_model,
            "perSsidSettings": {
                wireless: {
                    "bandOperationMode": ssid_0_mode,
                    "bandSteeringEnabled": ssid_0_steer_client,
                },
                guest: {
                    "bandOperationMode": ssid_1_mode,
                    "bandSteeringEnabled": ssid_1_steer_client,
                },
                iot: {
                    "bandOperationMode": ssid_2_mode,
                    "bandSteeringEnabled": ssid_2_steer_client,
                }
            },
    }   
            print(rf_profile_data)
            create_rf_profile_url = f"https://api.meraki.com/api/v1/networks/{network_id}/wireless/rfProfiles"
            response = requests.post(create_rf_profile_url, headers=headers, json=rf_profile_data)
            if response.status_code == 201:
                rf_profile_id = response.json()['id']
                output_messages.append(f"RF profile created with ID: {rf_profile_id}")
                # 3) Get APs for the given network
                get_aps_url = f"https://api.meraki.com/api/v1/networks/{network_id}/devices"
                response = requests.get(get_aps_url, headers=headers)
                if response.status_code == 200:
                    aps = response.json()
                    ap_serials = [ap['serial'] for ap in aps if ap['model'].startswith('MR')]
                    output_messages.append(f"Access Points with MR model: {ap_serials}")
                    for serial in ap_serials:
                        update_ap_rf_profile_url = f"https://api.meraki.com/api/v1/devices/{serial}/wireless/radio/settings"
                        ap_rf_profile_data = {
                            "rfProfileId": rf_profile_id
                        }
                        response = requests.put(update_ap_rf_profile_url, headers=headers, json=ap_rf_profile_data)
                        if response.status_code == 200:
                            output_messages.append(f"RF profile assigned to AP with serial: {serial} successfully!")
                        else:
                            output_messages.append(f"Failed to assign RF profile to AP with serial: {serial}. Error: {response.text}")
                else:
                    output_messages.append(f"Failed to get APs. Error: {response.text}")
            else:
                output_messages.append(f"Failed to create RF profile. Error: {response.text}")
        else:
            output_messages.append(f"Failed to gather SSID info. Error: {res.status_code}")
    return render(request, 'clone_rf_results.html',  {'output_messages': output_messages})
@user_passes_test(user_is_admin, login_url='invalid_login')
@login_required
def update_device_info(request):
    update_device_info_task.delay()
    return redirect('network')
@login_required
def network_view(request):
    device_info = Device_Info.objects.all()
    unique_networks = set(device.networkName for device in device_info)
    sorted_networks = sorted(unique_networks)
    context = {
            'networks': sorted_networks,
            'device_info': device_info
        }
    return render(request, 'network.html', context)
@user_passes_test(user_is_admin, login_url='invalid_login')
def webex_slave_bot(request):
    return render(request, 'webex_slave_bot.html')
@login_required
def microsoft_portals(request):
    return render(request, 'microsoft_portals.html')

@login_required
def my_projects_view(request):
    return render(request, 'my_projects.html')
@login_required
def project_dashboard_view(request):
    return render(request, 'project_dashboard.html')

def protected_serve(request, path, insecure=False, **kwargs):
    """
    View that serves static files, but with added MIME types.
    """
    response = serve(request, path, insecure=insecure, **kwargs)
    if path.endswith('.js'):
        response['Content-Type'] = 'application/javascript'
    return response

def update_site(request, site_id):
    site = get_object_or_404(Site, id=site_id)
    if request.method == 'POST':
        attributes = [
    'cleanliness_rating',
    'difficulty_rating',
    'air_conditioning_functioning',
    'idf_mdf_door_locked',
    'rack_grounding',
    'idf_mdf_clean_clear',
    'ups_functioning',
    'appropriate_size_cables',
    'idf_mdf_cable_managed',
    'temperature_humidity_sensors_setup',
    'ups_logic_monitor_setup',
    'trashcan',
    'devices_dual_power',
    'fiber_undamaged',
    'devices_labeled',
    'comments',
    'address',
    'lat',
    'lng'
]

        for attribute in attributes:
            setattr(site, attribute, request.POST.get(attribute, False))
        site.save()
        return render(request, 'site_update.html', {'site': site})
    return render(request, 'site_update.html', {'site': site})

from django.shortcuts import render, redirect
from .forms import FeatureRequestForm
@login_required
def feature_request_view(request):
    if request.method == 'POST':
        form = FeatureRequestForm(request.POST)
        if form.is_valid():
            feature_request = form.save(commit=False)
            feature_request.user = request.user  
            feature_request.save()
            return redirect('user_feature_requests')
    else:
        form = FeatureRequestForm()

    return render(request, 'feature_request_form.html', {'form': form})
def user_feature_requests(request):
    feature_requests = FeatureRequest.objects.filter(user=request.user)
    return render(request, 'user_feature_requests.html', {'feature_requests': feature_requests})