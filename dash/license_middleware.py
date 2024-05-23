from django.shortcuts import redirect
from django.urls import reverse
from map.models import Org_Info

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
            if org.is_setup and org.license == '' and not request.path.startswith(reverse('update_license')) and not request.path.startswith(reverse('update_org_license')):
                return redirect('update_license')
        except Org_Info.DoesNotExist:
            # If no Org_Info exists, proceed normally
            pass
        
        return self.get_response(request)