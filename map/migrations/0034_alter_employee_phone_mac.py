# Generated by Django 4.2.1 on 2023-12-28 19:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('map', '0033_alter_employee_phone'),
    ]

    operations = [
        migrations.AlterField(
            model_name='employee',
            name='phone_mac',
            field=models.CharField(default='', max_length=100, null=True),
        ),
    ]
