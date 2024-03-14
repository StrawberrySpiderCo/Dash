# context_processors.py

from .models import Org_Info

def org_info(request):
    org_info = Org_Info.objects.first()  # Get the organization info object (you may need to adjust this query)
    return {'org_info': org_info}
