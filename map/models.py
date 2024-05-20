# Create your models here.
from django.contrib.postgres.fields import JSONField
from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import User as AuthUser
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.contrib.auth.models import AbstractUser

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    isLdap = models.BooleanField(default=False)

    class Meta:
        db_table = 'map_user_profile'

class Markers(models.Model):
    name = models.CharField(max_length=100)
    lat = models.DecimalField(max_digits=9, decimal_places=6)
    lng = models.DecimalField(max_digits=9, decimal_places=6)
    icon = models.CharField(max_length=50)
    mplsNetwork = models.BooleanField()
    routerIp = models.CharField(max_length=20, blank=True)


class Site(models.Model):
    name = models.CharField(max_length=100,blank=True)
    networkId = models.CharField(max_length=100, default='',blank=True)
    webex_id = models.CharField(max_length=250, default='',null=True,blank=True)
    networkName = models.CharField(max_length=100, default='',null=True,blank=True)
    webexName = models.CharField(max_length=100, default='',null=True,blank=True)
    address = models.CharField(max_length=100,blank=True)
    lat  = models.CharField(max_length=100,blank=True)
    lng = models.CharField(max_length=100,blank=True)
    wanIp = models.CharField(max_length=100,blank=True)
    wan2Ip = models.CharField(max_length=100,blank=True)
    comments = models.CharField(max_length=1000, default='Test',null=True,blank=True)
    link = models.CharField(max_length=100,blank=True)
    opHr = models.CharField(max_length=100,blank=True)
    cleanliness_rating = models.IntegerField(null=True, default=1,blank=True)
    difficulty_rating = models.IntegerField(null=True, default=1,blank=True)
    rack_grounding = models.BooleanField(null=True,blank=True)
    idf_mdf_door_locked = models.BooleanField(null=True,blank=True)
    air_conditioning_functioning = models.BooleanField(null=True,blank=True)
    ups_functioning = models.BooleanField(null=True,blank=True)
    ups_logic_monitor_setup = models.BooleanField(null=True,blank=True)
    temperature_humidity_sensors_setup = models.BooleanField(null=True,blank=True)
    idf_mdf_cable_managed = models.BooleanField(null=True,blank=True)
    appropriate_size_cables = models.BooleanField(null=True,blank=True)
    idf_mdf_clean_clear = models.BooleanField(null=True,blank=True)
    devices_labeled = models.BooleanField(null=True,blank=True)
    fiber_undamaged = models.BooleanField(null=True,blank=True)
    devices_dual_power = models.BooleanField(null=True,blank=True)
    trashcan = models.BooleanField(null=True,blank=True)
    router_sn = models.CharField(max_length=100, default='',blank=True)
    vlans = models.JSONField(default=dict,blank=True)
    clients = models.JSONField(default=dict,blank=True)
    available = models.JSONField(default=dict,blank=True)
    def __str__(self):
        return self.name

class Device_Info(models.Model):
    serial = models.CharField(max_length=100)
    mac = models.CharField(max_length=100)
    url = models.CharField(max_length=1000)
    networkId = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    model = models.CharField(max_length=100)
    firmware= models.CharField(max_length=100)
    productType = models.CharField(max_length=100)
    networkName = models.CharField(max_length = 100)

class Client_Info(models.Model):
    client_id = models.CharField(max_length=100)
    mac = models.CharField(max_length=100, unique=True)
    network_name = models.CharField(max_length=100, default='')
    description = models.CharField(max_length=100)
    ip = models.CharField(max_length=100, unique=True)
    ip6 = models.CharField(max_length=100)
    ip6Local = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    firstSeen = models.CharField(max_length=100)
    lastSeen = models.CharField(max_length=100)
    manufacturer = models.CharField(max_length=100)
    os = models.CharField(max_length=100)
    deviceTypePrediction = models.CharField(max_length=100)
    recentDeviceSerial = models.CharField(max_length=100)
    recentDeviceName = models.CharField(max_length=100)
    recentDeviceMac = models.CharField(max_length=100)
    recentDeviceConnection = models.CharField(max_length=100)
    ssid = models.CharField(max_length=100)
    vlan = models.CharField(max_length=100)
    switchport = models.CharField(max_length=100)
    usage = models.JSONField() 
    status = models.CharField(max_length=100)
    notes = models.CharField(max_length=100)
    groupPolicy8021x = models.CharField(max_length=100)
    adaptivePolicyGroup = models.CharField(max_length=100)
    smInstalled = models.CharField(max_length=100)
    pskGroup = models.CharField(max_length=100)

class NetworkDevice(models.Model):
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    enable_password = models.CharField(max_length=100, default='', null=True)
    ip_address = models.CharField(max_length=200)
    model = models.CharField(max_length=200, default='', null=True)
    hostname = models.CharField(max_length=200, default='', null=True)
    make = models.CharField(max_length=200, default='', null=True)
    serial_number = models.CharField(max_length=200, default='', null=True)
    online = models.BooleanField(default=False)
    firmware_version = models.CharField(max_length=200, default='', null=True)
    device_type = models.CharField(max_length=200, default='', null=True)
    image = models.CharField(max_length=200, default='', null=True)
    ansible_status = models.CharField(max_length=200, default='', null=True)
    startup_config = models.TextField(default='', null=True)

    def __str__(self):
        return self.ip_address

class NetworkInterface(models.Model):
    device = models.ForeignKey(NetworkDevice, on_delete=models.CASCADE, related_name='interfaces')
    mode = models.CharField(max_length=100, null=True, blank=True)
    vlan = models.CharField(max_length=100, null=True, blank=True)
    voice_vlan = models.CharField(max_length=100, null=True, blank=True)
    native_vlan = models.CharField(max_length=100, null=True, blank=True)
    allowed_vlans = models.CharField(max_length=1000, null=True, blank=True)
    encapsulation = models.CharField(max_length=100, null=True, blank=True)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=255, null=True, blank=True)
    mac_address = models.CharField(max_length=17, null=True, blank=True) 
    mtu = models.PositiveIntegerField()
    bandwidth = models.PositiveIntegerField()
    media_type = models.CharField(max_length=50, null=True, blank=True)
    duplex = models.CharField(max_length=50, null=True, blank=True)
    line_protocol = models.CharField(max_length=50, null=True, blank=True)
    oper_status = models.CharField(max_length=50, null=True, blank=True)
    interface_type = models.CharField(max_length=50, null=True, blank=True)
    ipv4_address = models.CharField(max_length=50, null=True, blank=True)
    ipv4_subnet = models.CharField(max_length=50, null=True, blank=True)
    short_name = models.CharField(max_length=17, null=True, blank=True)
    def __str__(self):
        return f"{self.device} - {self.name}"
    
    
class NetworkTask(models.Model):
    device = models.ForeignKey(NetworkDevice, on_delete=models.CASCADE, related_name='tasks')
    result = models.CharField(max_length=200)
    start_time = models.CharField(max_length=200)
    end_time = models.CharField(max_length=200)
    duration = models.CharField(max_length=200)
    name = models.CharField(max_length=100)
    uid = models.CharField(max_length=250)
    task_result = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    msg =  models.CharField(max_length=255, null=True, blank=True)
    def __str__(self):
        return f"{self.device} - {self.name} - {self.result} - Sent at: {self.start_time}"

    class Meta:
        """
        Meta class to define additional properties for the model.
        """

        # Ordering of instances by creation time, with most recent first
        ordering = ['-created_at']

class RunningConfig(models.Model):
    """
    Model to store the running configuration of a network device.
    """

    # Foreign key to link each configuration to its corresponding device
    device = models.ForeignKey(NetworkDevice, on_delete=models.CASCADE, related_name='running_configs')

    # Text field to store the actual configuration content
    config_text = models.TextField()

    # Timestamp to track when the configuration was created
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        """
        Meta class to define additional properties for the model.
        """
        # Name for the database table
        db_table = 'running_configs'

        # Ordering of instances by creation time, with most recent first
        ordering = ['-created_at']

    def __str__(self):
        """
        Method to represent instances of this model as strings.
        """
        return f"Configuration for {self.device} created at {self.created_at}"

class Org_Info(models.Model):
    org_name = models.CharField(max_length=200, default='')
    repo_name = models.CharField(max_length=200, default='')
    client_count = models.PositiveIntegerField(default=0)
    site_count = models.PositiveIntegerField(default=0)
    network_device_ips = models.JSONField(default=list)
    admin_group = models.CharField(max_length=200, default='')
    tech_group = models.CharField(max_length=200, default='')
    dc_ip_address = models.CharField(max_length=200, default='')
    bind_account = models.CharField(max_length=200, default='')
    bind_password = models.CharField(max_length=200, default='')
    valid = models.BooleanField(default=False)
    license = models.CharField(max_length=200, default='')
    valid_time = models.CharField(max_length=200, default='')
    meraki_api_key = models.CharField(max_length=200, default='', null=True)
    organization_address = models.TextField(max_length=200,blank=True, null=True)
    contact_email = models.EmailField(blank=True, null=True)
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    industry = models.CharField(max_length=100, blank=True, null=True)
    organization_logo = models.ImageField(upload_to='org_logos/', blank=True, null=True)
    ssh_username = models.CharField(max_length=200, default='', null=True)
    ssh_password = models.CharField(max_length=200, default='', null=True)
    ssh_enable_password = models.CharField(max_length=200, default='', null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)
    admin_username = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return self.org_name
    def save(self, *args, **kwargs):
        # Check if there's already an existing Org_Info object
        if Org_Info.objects.exists() and not self.pk:
            raise ValidationError("Only one Org_Info object can exist.")
        
        super().save(*args, **kwargs)  # Call the original save method
    
    
class FeatureRequest(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    status = models.CharField(max_length=20, default='pending')
    created_date = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE,  default=1)

    def __str__(self):
        return self.title

class Employee(models.Model):
    first_name = models.CharField(max_length=100, default='')
    last_name = models.CharField(max_length=100, default='', null=True)
    display_name = models.CharField(max_length=100, default='')
    mail = models.CharField(max_length=100, null=True)
    webex_id = models.CharField(max_length=1000, null=True)
    azure_id = models.CharField(max_length=1000, null=True)
    phone = models.JSONField(default=dict)
    badge_number = models.CharField(max_length=100, default='', null=True)
    phone_mac = models.CharField(max_length=100, default='', null=True)
    site = models.CharField(max_length=1000, null=True)
    title = models.CharField(max_length=1000, null=True)
    manager = models.CharField(max_length=1000, null=True)
    hire_date = models.CharField(max_length=1000, null=True)
    upn = models.CharField(max_length=1000, null=True)
    givenName = models.CharField(max_length=1000, null=True)
    webex_last_act = models.CharField(max_length=1000, null=True)
    extension = models.CharField(max_length=1000, null=True)
    webex_lic = models.JSONField(default=dict)
    webex_dev_id = models.CharField(max_length=1000, null=True)
    webex_loc_id = models.CharField(max_length=150, default='', null=True)
    webex_model = models.CharField(max_length=150, default='', null=True)
    def __str__(self):
        return self.display_name

