from django.http import HttpResponseForbidden

class BlockIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        blocked_ips = ['129.226.220.254', '8.36.86.52','162.158.189.40']  # Add more IPs to block if needed
        client_ip = request.META.get('HTTP_X_FORWARDED_FOR')
        if client_ip:
            ipList = client_ip.split(',')
            oneIp = ipList[0]
        else:
            oneIp = ''

        if oneIp in blocked_ips:
            return HttpResponseForbidden()

        response = self.get_response(request)
        return response
