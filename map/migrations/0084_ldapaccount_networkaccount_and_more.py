# Generated by Django 4.2.1 on 2024-05-23 14:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('map', '0083_alter_org_info_free_trail_used'),
    ]

    operations = [
        migrations.CreateModel(
            name='LdapAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('admin_group', models.CharField(default='', max_length=200)),
                ('tech_group', models.CharField(default='', max_length=200)),
                ('dc_ip_address', models.CharField(default='', max_length=200)),
                ('bind_account', models.CharField(default='', max_length=200)),
                ('bind_password', models.CharField(default='', max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='NetworkAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ssh_username', models.CharField(default='', max_length=200, null=True)),
                ('ssh_password', models.CharField(default='', max_length=200, null=True)),
                ('ssh_enable_password', models.CharField(default='', max_length=200, null=True)),
                ('network_device_ips', models.JSONField(default=list)),
                ('meraki_api_key', models.CharField(default='', max_length=200, null=True)),
                ('client_count', models.PositiveIntegerField(default=0)),
            ],
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='admin_group',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='bind_account',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='bind_password',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='client_count',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='dc_ip_address',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='meraki_api_key',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='network_device_ips',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='ssh_enable_password',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='ssh_password',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='ssh_username',
        ),
        migrations.RemoveField(
            model_name='org_info',
            name='tech_group',
        ),
    ]
