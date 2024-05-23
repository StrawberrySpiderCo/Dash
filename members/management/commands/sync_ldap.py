from django.core.management.base import BaseCommand
from django_auth_ldap.config import LDAPSearch
import ldap
from django.contrib.auth.models import User, Group
from map.models import Org_Info, Profile,LdapAccount

class Command(BaseCommand):
    help = 'Sync LDAP data with Django models'

    def handle(self, *args, **kwargs):
        profiles_to_delete = Profile.objects.filter(isLdap=True)
        users_to_delete = User.objects.filter(profile__in=profiles_to_delete)
        users_to_delete.delete()
        profiles_to_delete.delete()
        org = LdapAccount.objects.get()
        # LDAP server connection settings
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        conn = ldap.initialize(f'ldap://{org.dc_ip_address}')
        conn.simple_bind_s(org.bind_account, org.bind_password)

        # Search for users
        admin_search_base = org.admin_group
        tech_search_base = org.tech_group
        user_search_filter = '(objectClass=user)'
        user_attributes = ['sAMAccountName', 'givenName', 'sn', 'mail']
        admin_user_results = conn.search_s(admin_search_base, ldap.SCOPE_SUBTREE, user_search_filter, user_attributes)
        tech_user_results = conn.search_s(tech_search_base, ldap.SCOPE_SUBTREE, user_search_filter, user_attributes)
        django_admin_group = Group.objects.get(name='admin')
        django_tech_group = Group.objects.get(name='tech')
        for dn, entry in admin_user_results:
            if isinstance(entry, dict):
                username = entry['sAMAccountName'][0].decode('utf-8')
                first_name = entry.get('givenName', [b''])[0].decode('utf-8')
                last_name = entry.get('sn', [b''])[0].decode('utf-8')
                email = entry.get('mail', [b''])[0].decode('utf-8')
                if username != org.admin_username:
                    user, created = User.objects.get_or_create(
                        username=username,
                        defaults={'first_name': first_name, 'last_name': last_name, 'email': email}
                    )

                    # Set the isLdap field
                    profile, _ = Profile.objects.get_or_create(user=user)
                    profile.isLdap = True
                    profile.save()

                    # Add user to groups
                    user.groups.add(django_admin_group)
                    user.groups.add(django_tech_group)
        for dn, entry in tech_user_results:
            if isinstance(entry, dict):
                username = entry['sAMAccountName'][0].decode('utf-8')
                first_name = entry.get('givenName', [b''])[0].decode('utf-8')
                last_name = entry.get('sn', [b''])[0].decode('utf-8')
                email = entry.get('mail', [b''])[0].decode('utf-8')

                if username != org.admin_username:
                    user, created = User.objects.get_or_create(
                        username=username,
                        defaults={'first_name': first_name, 'last_name': last_name, 'email': email}
                    )

                    # Set the isLdap field
                    profile, _ = Profile.objects.get_or_create(user=user)
                    profile.isLdap = True
                    profile.save()
                    user.groups.add(django_tech_group)
        self.stdout.write(self.style.SUCCESS('Successfully synced LDAP data'))