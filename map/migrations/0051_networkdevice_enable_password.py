# Generated by Django 4.2.1 on 2024-03-24 03:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('map', '0050_networkdevice_online'),
    ]

    operations = [
        migrations.AddField(
            model_name='networkdevice',
            name='enable_password',
            field=models.CharField(default='', max_length=100, null=True),
        ),
    ]
