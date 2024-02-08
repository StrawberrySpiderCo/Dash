from django.shortcuts import render
from django import forms
from django.contrib.staticfiles.views import serve
from django.shortcuts import render
from django.contrib.auth.decorators import login_required

def user_is_admin(user):
    return user.groups.filter(name='Admins').exists()

class IpForm(forms.Form):
    router_ip = forms.CharField(label='Router IP address', max_length=15)

@login_required
def projects_view(request):
    return render(request, 'projects.html')

@login_required
def meetings_view(request):
    return render(request, 'meetings.html')
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