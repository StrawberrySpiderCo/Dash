from django import forms
from django.contrib.auth.forms import UserCreationForm
import csv
from io import TextIOWrapper
from .models import FeatureRequest
from django.contrib.auth.models import User
from .models import Org_Info

class FeatureRequestForm(forms.ModelForm):
    class Meta:
        model = FeatureRequest
        fields = ['title', 'description']

class AdminCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']
class OrgInfoForm(forms.ModelForm):
    network_device_ips = forms.CharField(label='Network Device IPs', widget=forms.Textarea(attrs={'rows': 5}), required=False)
    csv_file = forms.FileField(label='Upload CSV File', required=False)

    class Meta:
        model = Org_Info
        fields = ['org_name', 'contact_email', 'contact_phone', 'site_count','meraki_api_key','ssh_username', 'ssh_password']
    def __init__(self, *args, **kwargs):
       super(OrgInfoForm, self).__init__(*args, **kwargs)
       self.fields['meraki_api_key'].required = False  # Set the Meraki API key field as not required

    def clean_network_device_ips(self):
        data = self.cleaned_data['network_device_ips']
        if data:
            ips = [ip.strip() for ip in data.replace(',', '\n').split('\n')]
            for ip in ips:
                if not ip:
                    raise forms.ValidationError('Invalid IP address format.')
            return ips

    def clean_csv_file(self):
        data = self.cleaned_data['csv_file']
        if data:
            ips = []
            try:
                csv_data = TextIOWrapper(data.file, encoding='utf-8')
                reader = csv.reader(csv_data)
                for row in reader:
                    ips.extend(row)
            except Exception as e:
                raise forms.ValidationError('Error processing CSV file: {}'.format(str(e)))
            return ips
        return None

    def clean(self):
        cleaned_data = super().clean()
        network_device_ips = cleaned_data.get('network_device_ips')
        csv_file = cleaned_data.get('csv_file')
        if not network_device_ips and not csv_file:
            raise forms.ValidationError('Please provide either network device IPs or upload a CSV file.')
        return cleaned_data