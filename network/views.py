from django.shortcuts import render
from celery import chord
from django.shortcuts import redirect
from django import forms
from json import loads
from django.contrib.staticfiles.views import serve
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import login_required
from map.models import NetworkDevice, NetworkInterface, NetworkTask,RunningConfig
from map.tasks import set_interface, set_l2interface, update_port_info, gather_running_configs, gather_startup_configs,push_startup_configs, update_device, setup_network_devices,cycle_port_task
from django.contrib.auth.decorators import user_passes_test
from django.http import JsonResponse
from difflib import unified_diff
import json
from time import sleep
import logging

logger_network = logging.getLogger('network')

def user_is_admin(user):
    return user.groups.filter(name='admin').exists()


class IpForm(forms.Form):
    router_ip = forms.CharField(label='Router IP address', max_length=15)

@login_required
def device_details(request, device_id):
    try:
        is_admin = request.user.groups.filter(name='admin').exists()
        device = get_object_or_404(NetworkDevice, pk=device_id)
        sorted_interfaces = NetworkInterface.objects.filter(device=device).order_by('name')
        
        logger_network.info(f"User {request.user.username} accessed device details for device_id: {device_id}, admin status: {is_admin}")
        
        return render(request, 'device_details.html', {'device': device, 'device_interfaces': sorted_interfaces, 'is_admin': is_admin})
    except NetworkDevice.DoesNotExist:
        logger_network.warning(f"Device with device_id: {device_id} not found.")
        raise
    except Exception as e:
        logger_network.error(f"An error occurred while accessing device details for device_id: {device_id}: {str(e)}")
        raise



@user_passes_test(user_is_admin, login_url='invalid_login')
@login_required
def update_device_info(request):
    #update_device_info_task.delay()
    return redirect('network')

@login_required
def port_view(request, device_id):
    try:
        is_admin = request.user.groups.filter(name='admin').exists()
        device = get_object_or_404(NetworkDevice, pk=device_id)
        sorted_interfaces = NetworkInterface.objects.filter(device=device).order_by('name')
        
        logger_network.info(f"User {request.user.username} accessed port view for device_id: {device_id}, admin status: {is_admin}")
        
        return render(request, 'port_view.html', {'device': device, 'device_interfaces': sorted_interfaces, 'is_admin': is_admin})
    except NetworkDevice.DoesNotExist:
        logger_network.warning(f"Device with device_id: {device_id} not found.")
        raise
    except Exception as e:
        logger_network.error(f"An error occurred while accessing port view for device_id: {device_id}: {str(e)}")
        raise


@login_required
def config_view(request, device_id):
    try:
        is_admin = request.user.groups.filter(name='admin').exists()
        device = get_object_or_404(NetworkDevice, pk=device_id)
        device_configs = RunningConfig.objects.filter(device=device)
        
        logger_network.info(f"User {request.user.username} accessed config view for device_id: {device_id}, admin status: {is_admin}")
        
        return render(request, 'config_view.html', {'device': device, 'device_configs': device_configs, 'is_admin': is_admin})
    except NetworkDevice.DoesNotExist:
        logger_network.warning(f"Device with device_id: {device_id} not found.")
        raise
    except Exception as e:
        logger_network.error(f"An error occurred while accessing config view for device_id: {device_id}: {str(e)}")
        raise


@user_passes_test(user_is_admin, login_url='invalid_login')
@login_required
def edit_ports(request):
    try:
        logger_network.info(f"User {request.user.username} accessed edit ports view.")
        
        if request.method == 'POST':
            selected_ports_str = request.POST.get('selected_ports')
            try:
                selected_ports = json.loads(selected_ports_str)
                logger_network.info(f"Selected ports (JSON): {selected_ports}")
            except json.JSONDecodeError:
                selected_ports = selected_ports_str.split()
                logger_network.info(f"Selected ports (split): {selected_ports}")

            host = request.POST.get('ip_address')
            desired_state = request.POST.get('desiredState')
            mode = request.POST.get('mode')
            vlan = request.POST.get('vlan')
            voice_vlan = request.POST.get('voiceVlan')
            native_vlan = request.POST.get('nativeVlan')
            allowed_vlans = request.POST.get('allowedVlans')

            if allowed_vlans:
                allowed_vlans = [vlan.strip() for vlan in allowed_vlans.split(',')]
                logger_network.info(f"Allowed VLANs: {allowed_vlans}")

            try:
                vlan = int(vlan) if vlan else None
            except ValueError:
                vlan = None

            try:
                voice_vlan = int(voice_vlan) if voice_vlan else None
            except ValueError:
                voice_vlan = None

            try:
                native_vlan = int(native_vlan) if native_vlan else None
            except ValueError:
                native_vlan = None

            encapsulation = request.POST.get('encapsulation')
            logger_network.info(f"Host: {host}, Desired State: {desired_state}, Mode: {mode}, VLAN: {vlan}, Voice VLAN: {voice_vlan}, Native VLAN: {native_vlan}, Encapsulation: {encapsulation}")

            set_interface.delay(host, selected_ports, desired_state)
            logger_network.info(f"Set interface task initiated for host: {host}, selected ports: {selected_ports}, desired state: {desired_state}")

            if mode != 'None':
                set_l2interface.delay(host, selected_ports, mode, vlan, voice_vlan, native_vlan, allowed_vlans, encapsulation)
                logger_network.info(f"Set L2 interface task initiated for host: {host}, mode: {mode}, VLAN: {vlan}, Voice VLAN: {voice_vlan}, Native VLAN: {native_vlan}, Allowed VLANs: {allowed_vlans}, Encapsulation: {encapsulation}")

            data = {
                'success': True,
                'message': 'Yippee'
            }
            return JsonResponse(data)
    except Exception as e:
        logger_network.error(f"An error occurred in edit ports view: {str(e)}")
        raise

        
@login_required
def tasks_view(request, device_id):
    device = get_object_or_404(NetworkDevice, pk=device_id)
    device_tasks = NetworkTask.objects.filter(device=device)
    return render(request, 'network_tasks.html', {'device': device, 'device_tasks': device_tasks})


@login_required
def fetch_tasks(request, device_id):
    device = get_object_or_404(NetworkDevice, pk=device_id)
    device_tasks = NetworkTask.objects.filter(device=device)
    tasks_data = [{'result': task.result, 'start_time': task.created_at, 'end_time': task.end_time, 'duration': task.duration, 'name': task.name, 'uid': task.uid, 'task_result': task.task_result, 'msg': task.msg} for task in device_tasks]
    return JsonResponse({'device_tasks': tasks_data})

@login_required
def fetch_configs(request, device_id):
    try:
        device = get_object_or_404(NetworkDevice, pk=device_id)
        hostname = device.ip_address
        
        logger_network.info(f"User {request.user.username} initiated config fetch tasks for device_id: {device_id}, hostname: {hostname}")
        
        gather_startup_configs.delay(hostname)
        logger_network.info(f"Gather startup configs task initiated for hostname: {hostname}")
        
        gather_running_configs.delay(hostname)
        logger_network.info(f"Gather running configs task initiated for hostname: {hostname}")
        
        return JsonResponse({'device_tasks': ''})
    except NetworkDevice.DoesNotExist:
        logger_network.warning(f"Device with device_id: {device_id} not found.")
        raise
    except Exception as e:
        logger_network.error(f"An error occurred while initiating config fetch tasks for device_id: {device_id}, hostname: {hostname}: {str(e)}")
        raise

@login_required
def fetch_device_info(request, device_id):
    try:
        device = get_object_or_404(NetworkDevice, pk=device_id)
        hostname = device.ip_address
        
        logger_network.info(f"User {request.user.username} initiated device info update for device_id: {device_id}, hostname: {hostname}")
        
        update_device.delay(hostname)
        logger_network.info(f"Update device task initiated for hostname: {hostname}")
        
        return JsonResponse({'device_info': ''})
    except NetworkDevice.DoesNotExist:
        logger_network.warning(f"Device with device_id: {device_id} not found.")
        raise
    except Exception as e:
        logger_network.error(f"An error occurred while initiating device info update for device_id: {device_id}, hostname: {hostname}: {str(e)}")
        raise


@user_passes_test(user_is_admin, login_url='invalid_login')
@login_required
def cycle_port(request):
    try:
        logger_network.info(f"User {request.user.username} accessed cycle port view.")
        
        if request.method == 'POST':
            selected_ports_str = request.POST.get('selected_ports')
            try:
                selected_ports = json.loads(selected_ports_str)
                logger_network.info(f"Selected ports (JSON): {selected_ports}")
            except json.JSONDecodeError:
                selected_ports = selected_ports_str.split()
                logger_network.info(f"Selected ports (split): {selected_ports}")

            host = request.POST.get('ip_address')
            logger_network.info(f"Initiating cycle port task for host: {host}, selected ports: {selected_ports}")
            
            cycle_port_task.delay(host, selected_ports)
            logger_network.info(f"Cycle port task initiated for host: {host}, selected ports: {selected_ports}")

            data = {
                'success': True,
                'message': 'Yippee'
            }
            return JsonResponse(data)
    except Exception as e:
        logger_network.error(f"An error occurred in cycle port view: {str(e)}")
        raise

    
@user_passes_test(user_is_admin, login_url='invalid_login')
@login_required
def push_configs(request, device_id):
    try:
        if request.method == 'POST':
            device = get_object_or_404(NetworkDevice, pk=device_id)
            hostname = device.ip_address

            running_config_text = request.POST.get('runningConfigText', '')
            
            logger_network.info(f"User {request.user.username} initiated push configs for device_id: {device_id}, hostname: {hostname}")
            
            push_startup_configs.delay(hostname, running_config_text)
            logger_network.info(f"Push startup configs task initiated for hostname: {hostname}")
            
            gather_startup_configs.delay(hostname)
            logger_network.info(f"Gather startup configs task initiated for hostname: {hostname}")

            return JsonResponse({'message': 'Config pushed successfully.'})
        else:
            logger_network.warning("Method not allowed for push configs view.")
            return JsonResponse({'error': 'Method not allowed.'}, status=405)
    except NetworkDevice.DoesNotExist:
        logger_network.warning(f"Device with device_id: {device_id} not found.")
        raise
    except Exception as e:
        logger_network.error(f"An error occurred in push configs view for device_id: {device_id}, hostname: {hostname}: {str(e)}")
        raise


@login_required
def fetch_all_devices_info(request):
    try:
        logger_network.info(f"User {request.user.username} initiated fetch all devices info.")
        
        setup_network_devices.delay()
        logger_network.info("Setup network devices task initiated.")
        
        return JsonResponse({'device_info': ''})
    except Exception as e:
        logger_network.error(f"An error occurred in fetch all devices info view: {str(e)}")
        raise


@login_required
def fetch_devices(request):
    if NetworkDevice.objects.exists():
            data = 'data'
    else:
        data = ''
    return JsonResponse({'devices': data})

@login_required
def network_view(request):
    device_info = NetworkDevice.objects.all().order_by('ip_address')
    
    context = {
            'device_info': device_info,
                        }
    return render(request, 'network.html', context)


def protected_serve(request, path, insecure=False, **kwargs):
    """
    View that serves static files, but with added MIME types.
    """
    response = serve(request, path, insecure=insecure, **kwargs)
    if path.endswith('.js'):
        response['Content-Type'] = 'application/javascript'
    return response
