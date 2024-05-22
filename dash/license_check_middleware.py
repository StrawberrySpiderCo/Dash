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
            # Check if the organization is set up and the license is not set
            if org.is_setup and org.organization_license is None:
                return redirect('update_license', org_id=org.org_id)
        except Org_Info.DoesNotExist:
            # If no Org_Info exists, proceed normally
            pass
        
        return self.get_response(request)