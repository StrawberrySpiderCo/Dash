# Generated by Django 4.2.1 on 2024-07-16 13:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('map', '0092_licenseserverstatus_org_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='licenseserverstatus',
            name='status',
            field=models.BooleanField(default=True),
        ),
    ]
