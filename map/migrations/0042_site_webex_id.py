# Generated by Django 4.2.1 on 2024-01-04 18:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('map', '0041_alter_site_address_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='site',
            name='webex_id',
            field=models.CharField(blank=True, default='', max_length=250, null=True),
        ),
    ]
