# Generated by Django 4.2.1 on 2023-07-27 22:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('map', '0009_site_clients_site_vlans'),
    ]

    operations = [
        migrations.AddField(
            model_name='site',
            name='available',
            field=models.JSONField(default=dict),
        ),
    ]
