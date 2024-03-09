# middleware.py

from django.shortcuts import redirect
from django.urls import reverse

class CheckUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated and not request.path.startswith(reverse('setup')):
            return redirect('setup')
        return self.get_response(request)
