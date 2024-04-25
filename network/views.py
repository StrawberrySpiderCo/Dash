from django.shortcuts import render
from django.shortcuts import redirect
from django import forms
from json import loads
from django.contrib.staticfiles.views import serve
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import login_required
from map.models import NetworkDevice, NetworkInterface
from map.tasks import update_device_info_task
from django.contrib.auth.decorators import user_passes_test


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
    return render(request, 'port_view.html', {'device': device, 'device_interfaces':device_interfaces})

def edit_ports(request):
    if request.method == 'POST':
        selected_ports = request.POST.getlist('selected_ports')
        vlan = request.POST.get('vlan')
        description = request.POST.get('description')

        #bulk_update_ports_task.delay(selected_ports, vlan, description)

        return render(request, 'port_edit_success.html')
    else:
        return render(request, 'port_edit_failure.html')

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
