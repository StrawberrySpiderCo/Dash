# middleware.py

from django.shortcuts import redirect
from django.urls import reverse
from django.contrib.auth import get_user_model

class CheckUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        User = get_user_model()
        if User.objects.exists():
            # At least one user exists, proceed with the request
            return self.get_response(request)
        elif not request.path.startswith(reverse('setup')):
            # No user exists and request is not already on the setup page
            return redirect('setup')
        else:
           # No user exists but request is already on the setup page, proceed
            return self.get_response(request)
        
from django.shortcuts import redirect
from django.urls import reverse
from map.models import Org_Info
from map.views import update_license

class LicenseCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Bypass the license check for admin pages
        if request.path.startswith(reverse('admin:index')):
            return self.get_response(request)
        
        try:
            org = Org_Info.objects.get()
            # Check if the organization is set up, the license is not set, and the request is not already for the update_license page
            if org.is_setup and org.license == '' and not request.path.startswith(reverse('update_license')):
                return redirect('update_license')
        except Org_Info.DoesNotExist:
            # If no Org_Info exists, proceed normally
            pass
        
        return self.get_response(request)