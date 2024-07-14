# middleware.py

import logging
import time

logger = logging.getLogger('dash')

class LoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start_time = time.time()
        response = self.get_response(request)
        duration = time.time() - start_time
        ip_address = self.get_client_ip(request)
        if request.path == '/ping_license_server/':
            pass
        else:
            logger.info(f"{request.method} {request.path} from {ip_address} completed in {duration:.2f}s")
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
