from django.contrib import admin
from django.contrib import admin

from .models import Site, Device_Info, Client_Info,Org_Info,FeatureRequest,Employee, NetworkDevice, RunningConfig

admin.site.register(Site)    
admin.site.register(Device_Info)  
admin.site.register(Client_Info)       
admin.site.register(Org_Info)
admin.site.register(Employee)
admin.site.register(FeatureRequest)
admin.site.register(NetworkDevice)
admin.site.register(RunningConfig)
# Register your models here.
