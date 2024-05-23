from django import forms
from django.contrib.auth.forms import UserCreationForm
import csv
from io import TextIOWrapper, StringIO
from io import BytesIO
from .models import FeatureRequest
from django.contrib.auth.models import User
from .models import Org_Info, NetworkAccount, LdapAccount
import ipaddress


class FeatureRequestForm(forms.ModelForm):
    class Meta:
        model = FeatureRequest
        fields = ['title', 'description']

class AdminCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']

class OrgInfoForm(forms.ModelForm):
    class Meta:
        model = Org_Info
        fields = [
            'org_name', 'contact_email', 'contact_phone'
        ]

class NetworkAccountForm(forms.ModelForm):
    network_device_ips = forms.CharField(
        label='Network Device IPs', 
        widget=forms.Textarea(attrs={'rows': 5}), 
        required=False
    )
    csv_file = forms.FileField(label='Upload CSV File', required=False)
    meraki_api_key = forms.CharField(label='Meraki API Key', required=False)

    class Meta:
        model = NetworkAccount
        fields = [
            'ssh_username', 'ssh_password', 'ssh_enable_password',
            'meraki_api_key', 'network_device_ips'
        ]

    def clean_network_device_ips(self):
        data = self.cleaned_data['network_device_ips']
        if data:
            ips = [ip.strip() for ip in data.replace(',', '\n').split('\n')]
            for ip in ips:
                if not ip:
                    raise forms.ValidationError('<span style="color:red;">Invalid IP address format.</span>')
            return ips

    def clean_csv_file(self):
        data = self.cleaned_data['csv_file']
        if data:
            ips = []
            try:
                csv_data = data.read().decode('utf-8')
                reader = csv.reader(StringIO(csv_data))
                for row in reader:
                    for cell in row:
                        # Check if the cell contains a valid IP address
                        ip = cell.strip()
                        if ipaddress.ip_address(ip):
                            ips.append(ip)
            except Exception as e:
                raise forms.ValidationError('<span style="color:red;">Error processing CSV file:</span> {}'.format(str(e)))
            if not ips:
                raise forms.ValidationError('<span style="color:red;">Uploaded CSV file does not contain any valid IP addresses.</span>')
            return ips
        return None


    def clean(self):
        cleaned_data = super().clean()
        network_device_ips = cleaned_data.get('network_device_ips')
        csv_file = cleaned_data.get('csv_file')

        if not network_device_ips and not csv_file:
            raise forms.ValidationError('<span style="color:red;">Please provide either network device IPs or upload a CSV file.</span>')

        if csv_file:
            # Check if the CSV file contains IPs
            csv_ips = self.clean_csv_file()
            if not csv_ips:
                raise forms.ValidationError('<span style="color:red;">Uploaded CSV file does not contain any IPs.</span>')

        return cleaned_data

class LdapAccountForm(forms.ModelForm):
    dc_ip_address = forms.CharField(label='LDAP Server IP Address (Optional)', max_length=100, required=False)
    bind_account = forms.CharField(label='Bind Account (Optional) e.g. CN=strawberry spider,OU=users,DC=test,DC=local', max_length=200, required=False)
    bind_password = forms.CharField(label='Bind Password (Optional) e.g. P@55w0rd1!', required=False)
    admin_group = forms.CharField(label='Admin Group DN (Optional) e.g. CN=Admins,OU=Groups,DC=test,DC=local', max_length=200, required=False)
    tech_group = forms.CharField(label='Tech Group DN (Optional) e.g. CN=Techs,OU=Groups,DC=test,DC=local', max_length=200, required=False)

    class Meta:
        model = LdapAccount
        fields = [
            'dc_ip_address', 'bind_account', 'bind_password',
            'admin_group', 'tech_group'
        ]
