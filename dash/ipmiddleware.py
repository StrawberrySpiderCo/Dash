import datetime

class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        forward_ip = request.META.get('HTTP_X_FORWARDED_FOR')
        real_ip = request.META.get('HTTP_X_REAL_IP')
        remote_ip = request.META.get('REMOTE_ADDR')

        ip_labels = {
            forward_ip: 'Forwarded IP',
            real_ip: 'Real IP',
            remote_ip: 'Remote IP',
        }

        # Split the forward_ip if it's not None or empty
        if forward_ip:
            ipList = forward_ip.split(',')
            oneIp = ipList[0]
        else:
            oneIp = ''

        # Add more IPs or IP ranges to exclude
        excluded_ips = ['52.202.255.79','18.139.118.202','3.106.118.111']

        # Determine the IP address and its corresponding label
        ip_address = ''
        ip_type = ''
        if oneIp not in excluded_ips:
            for ip in [forward_ip, real_ip, remote_ip]:
                if ip and ip not in excluded_ips:
                    ip_address = ip
                    ip_type = ip_labels.get(ip, 'Unknown IP')
                    break
        else:
            return self.get_response(request)

        # Get the response from the view
        response = self.get_response(request)

        # Get the response code
        response_code = response.status_code

        # Get the accessed URL
        accessed_url = request.path_info

        # Get the user information
        user = request.user
        username = user.username if user.is_authenticated else 'Anonymous User'

        current_datetime = datetime.datetime.now()
        log_message = f"{current_datetime} - User: {username}, Request from {ip_type}: {ip_address}, URL: {accessed_url}, Response code: {response_code}\n"

        return response
