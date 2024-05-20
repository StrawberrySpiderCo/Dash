from django.db import models

class LDAPUser(models.Model):
    username = models.CharField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField()
    ldap = models.BooleanField(default=True)
    admin = models.BooleanField(null=True)
    def __str__(self):
        return self.username

class LDAPGroup(models.Model):
    name = models.CharField(max_length=255, unique=True)
    members = models.ManyToManyField(LDAPUser)

    def __str__(self):
        return self.name