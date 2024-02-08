from django import forms
from .models import WikiEntry

class WikiEntryForm(forms.ModelForm):
    class Meta:
        model = WikiEntry
        fields = ['title', 'content']
