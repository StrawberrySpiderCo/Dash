# Generated by Django 4.2.7 on 2023-12-28 00:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('map', '0027_employee_phone'),
    ]

    operations = [
        migrations.AlterField(
            model_name='employee',
            name='phone',
            field=models.JSONField(default='{}'),
        ),
    ]
