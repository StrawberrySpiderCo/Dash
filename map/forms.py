from django import forms
import csv
from io import TextIOWrapper
from .models import FeatureRequest
from .models import Org_Info

class FeatureRequestForm(forms.ModelForm):
    class Meta:
        model = FeatureRequest
        fields = ['title', 'description']

class OrgInfoForm(forms.ModelForm):
    network_device_ips = forms.CharField(label='Network Device IPs', widget=forms.Textarea(attrs={'rows': 5}), required=False)
    csv_file = forms.FileField(label='Upload CSV File', required=False)

    class Meta:
        model = Org_Info
        fields = ['org_name', 'contact_email', 'contact_phone', 'site_count', 'organization_address', 'organization_logo','meraki_api_key']

    def clean_network_device_ips(self):
        data = self.cleaned_data['network_device_ips']
        if data:
            # Split the input by comma or newline
            ips = [ip.strip() for ip in data.replace(',', '\n').split('\n')]
            # Validate each IP address (you can add more sophisticated validation logic)
            for ip in ips:
                # Perform IP address validation
                # For simplicity, I'm just checking if the string is non-empty
                if not ip:
                    raise forms.ValidationError('Invalid IP address format.')
            return ips

    def clean_csv_file(self):
        data = self.cleaned_data['csv_file']
        if data:
            # Read and parse the CSV file
            ips = []
            try:
                # Decode the file contents to strings
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