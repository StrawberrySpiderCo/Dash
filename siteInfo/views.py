from django.shortcuts import render
from django import forms
from django.contrib.staticfiles.views import serve
from map.models import Site
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import login_required

def user_is_admin(user):
    return user.groups.filter(name='Admins').exists()

class IpForm(forms.Form):
    router_ip = forms.CharField(label='Router IP address', max_length=15)

@login_required
def site_details(request, site_id):
    site = get_object_or_404(Site, pk=site_id)
    return render(request, 'site_details.html', {'site': site})

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
@login_required
def sites_view(request):
    sites = Site.objects.all()
    return render(request, 'sites.html', {'sites': sites})