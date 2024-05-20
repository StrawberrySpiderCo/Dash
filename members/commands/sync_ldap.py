from django.core.management.base import BaseCommand
from django_auth_ldap.config import LDAPSearch
import ldap
from django.contrib.auth.models import User, Group
from map.models import Org_Info

class Command(BaseCommand):
    help = 'Sync LDAP data with Django models'

    def handle(self, *args, **kwargs):
        # Clear existing users and groups
        #User.objects.filter(ldap=True).delete()
        org = Org_Info.objects.get()
        # LDAP server connection settings
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        conn = ldap.initialize(f'ldap://{org.dc_ip_address}')
        conn.simple_bind_s(org.bind_account, org.bind_password)

        # Search for users
        admin_search_base = org.admin_group
        admin_user_search_filter = '(objectClass=user)'
        admin_user_attributes = ['sAMAccountName', 'givenName', 'sn', 'mail']
        admin_user_results = conn.search_s(admin_search_base, ldap.SCOPE_SUBTREE, admin_user_search_filter, admin_user_attributes)
        django_admin_group = Group.objects.get(name='admin')
        django_tech_group = Group.objects.get(name='tech')
        for dn, entry in admin_user_results:
            if isinstance(entry, dict):
                username = entry['sAMAccountName'][0].decode('utf-8')
                first_name = entry.get('givenName', [b''])[0].decode('utf-8')
                last_name = entry.get('sn', [b''])[0].decode('utf-8')
                email = entry.get('mail', [b''])[0].decode('utf-8')

                # Create or update User
                user, created = User.objects.update_or_create(
                    username=username,
                    defaults={'first_name': first_name, 'last_name': last_name, 'email': email, 'ldap': True}
                )
                user.groups.add(django_admin_group)
                user.groups.add(django_tech_group)


        self.stdout.write(self.style.SUCCESS('Successfully synced LDAP data'))