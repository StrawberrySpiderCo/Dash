from django.contrib import admin
from django.contrib import admin

from .models import Site, Device_Info, Client_Info,Org_Info,FeatureRequest,Employee, NetworkDevice, RunningConfig, NetworkInterface, NetworkTask
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

# Customize the UserAdmin class if needed
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'ldap', 'is_staff', 'is_superuser')  # Customize the list display fields
    list_filter = ('ldap', 'is_staff', 'is_superuser')  # Add additional filters if needed

# Register the User model with the custom admin class
admin.site.register(User, CustomUserAdmin)

admin.site.register(Site)    
admin.site.register(Device_Info)  
admin.site.register(Client_Info)       
admin.site.register(Org_Info)
admin.site.register(Employee)
admin.site.register(FeatureRequest)
admin.site.register(NetworkDevice)
admin.site.register(RunningConfig)
admin.site.register(NetworkInterface)
admin.site.register(NetworkTask)
# Register your models here.
