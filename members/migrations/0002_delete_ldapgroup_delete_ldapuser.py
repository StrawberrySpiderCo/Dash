# Generated by Django 4.2.1 on 2024-05-19 18:14

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('members', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='LDAPGroup',
        ),
        migrations.DeleteModel(
            name='LDAPUser',
        ),
    ]
