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