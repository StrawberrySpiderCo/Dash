from django.shortcuts import render
from django.shortcuts import redirect
from django import forms
from json import loads
from django.contrib.staticfiles.views import serve
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import login_required
from map.models import NetworkDevice, NetworkInterface
from map.tasks import update_device_info_task, set_interface
from django.contrib.auth.decorators import user_passes_test
import json


def user_is_admin(user):
    return user.groups.filter(name='Admins').exists()


class IpForm(forms.Form):
    router_ip = forms.CharField(label='Router IP address', max_length=15)

@login_required
def device_details(request, device_id):
    device = get_object_or_404(NetworkDevice, pk=device_id)
    device_interfaces = NetworkInterface.objects.filter(device=device)
    return render(request, 'device_details.html', {'device': device, 'device_interfaces':device_interfaces})


@user_passes_test(user_is_admin, login_url='invalid_login')
@login_required
def update_device_info(request):
    update_device_info_task.delay()
    return redirect('network')

@login_required
def port_view(request, device_id):
    device = get_object_or_404(NetworkDevice, pk=device_id)
    device_interfaces = NetworkInterface.objects.filter(device=device)
    sorted_interfaces = sorted(device_interfaces, key=sort_ports)
    return render(request, 'port_view.html', {'device': device, 'device_interfaces': sorted_interfaces})

def sort_ports(interface):
    port_name = interface.name
    try:
        prefix, rest = port_name.split('/')
        card_number, port_number = rest.split('/')
        print(prefix, rest, card_number, port_number)
        card_number = int(card_number)
        port_number = int(port_number)
        return card_number, port_number
    except ValueError:
        return float('inf'), float('inf')
    

def edit_ports(request):
    port_list = []
    if request.method == 'POST':
        selected_ports_str = request.POST.get('selected_ports')
        selected_ports = json.loads(selected_ports_str)
        host = request.POST.get('ip_address')
        desired_state = request.POST.get('desiredState')
        mode = request.POST.get('mode')
        vlan = request.POST.get('vlan')
        voice_vlan = request.POST.get('')
        #port_list = [get_object_or_404(NetworkInterface, name=(port)).name for port in selected_ports]
        set_interface.delay(host, selected_ports, desired_state)
        return render(request, 'port_edit_success.html', {'selected_ports': selected_ports, 'host': host, 'desired_state': desired_state})
    else:
        return render(request, 'port_edit_failure.html')
    
  #var mode = document.querySelector('input[name="mode"]:checked').value;
  #
  #var vlan = document.getElementById('vlan').value;
  #var voiceVlan = document.getElementById('voiceVlan').value;
  #var nativeVlan = document.getElementById('nativeVlan').value;
  #var allowedVlans = document.getElementById('allowedVlans').value;
  #var encapsulation = document.getElementById('encapsulation').value;

@login_required
def network_view(request):
    device_info = NetworkDevice.objects.all()
    unique_networks = set(device.hostname for device in device_info)
    #sorted_networks = sorted(unique_networks)
    context = {
            #'networks': sorted_networks,
            'device_info': device_info
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
