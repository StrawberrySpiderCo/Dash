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
        logger.info(f"{request.method} {request.path} completed in {duration:.2f}s")
        return response
