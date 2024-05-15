"""dash URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from django.urls import path
from map import views as map
from siteInfo import views as sites
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from map.views import protected_serve
from members.views import login_user, logout_user
from tools import views as tools
from network import views as network
from wiki import views as wiki
from project import views as project

urlpatterns = [
    path('admin/', admin.site.urls),
    path('port_view/<int:device_id>/', network.port_view, name='port_view'),
    path('config/<int:device_id>/', network.config_view, name='config_view'),
    path('network/tasks/<int:device_id>/', network.tasks_view, name='tasks_view'),
    path('fetch/network/tasks/<int:device_id>/', network.fetch_tasks, name='fetch_tasks'),
    path('fetch/network/devices/', network.fetch_devices, name='fetch_devices'),
    path('fetch/network/configs/<int:device_id>/', network.fetch_configs, name='fetch_configs'),
    path('setup/', map.setup, name='setup'),
    path('edit_ports_results/', network.edit_ports, name='edit_ports'),
    path('setup/success/', map.success_setup, name='success_setup'),
    path('members/', include('members.urls')),
    path('members/', include('django.contrib.auth.urls')),
    path('', map.home_view, name='home'),
    path('site/<int:site_id>/', sites.site_details, name='site_details'),
    path('device_details/<int:device_id>/', network.device_details, name='device_details'),
    path('site/update/<int:site_id>/', sites.update_site, name='site_update'),
    path('map/', map.map_view, name='map'),
    path('getConfigDiff/', map.getConfigDiff, name='getConfigDiff'),
    path('wikis/', wiki.wikis_view, name='wikis'),
    path('tools/', tools.tools_view, name='tools'),
    path('network/', network.network_view, name='network'),
    path('update_device_info/', network.update_device_info, name='update_device_info'),
    path('update_vlan_info/', tools.update_vlan_info, name='update_vlan_info'),
    path('clone_rf/', tools.clone_rf, name='clone_rf'),
    path('sites/', sites.sites_view, name='sites'),
    path('ping/', map.ping_view, name="ping_view"),
    path('login/', login_user, name='login_user'),
    path('logout_user', logout_user, name="logout_user"),
    path('projects/', project.projects_view, name="projects"),
    path('static/Javascript', protected_serve),
    path('webex_slave_bot/', tools.webex_slave_bot ,name='webex_slave_bot'),
    path('multiplicity/', tools.multiplicity_view ,name='multiplicity'),
    path('ipam/', tools.ipam_view ,name='ipam'),
    path('rule_clone/', tools.rule_cloner_view ,name='rule_clone'),
    path('wireless_bomber/', tools.wireless_bomber_view ,name='wifi_bomb'),
    path('wireless_bomber_results/', tools.wireless_bomber_execution_view ,name='wireless_bomber_results'),
    path('purrception/', tools.purrception_view ,name='purrception'),
    path('purrception/results', tools.purrception_results ,name='purrception_results'),
    path('rule_cloner_results/', tools.rule_cloner ,name='rule_cloner_results'),
    path('wiki/', wiki.wiki_list, name='wiki_list'),
    path('entry/<int:pk>/', wiki.wiki_detail, name='wiki_detail'),
    path('entry/new/', wiki.wiki_new, name='wiki_new'),
    path('entry/<int:pk>/edit/', wiki.wiki_edit, name='wiki_edit'),
    path('home/', map.home_view, name='home'),
    path('feature_request/', map.feature_request_view, name='feature_request'),
    path('microsoft_portals/', tools.microsoft_portals, name='microsoft_portals'),
    path('user_feature_requests/', map.user_feature_requests, name='user_feature_requests'),
    path('meetings/', project.meetings_view, name='meetings'),
    path('my_projects/', project.my_projects_view, name='my_projects'),
    path('project_dashboard/', project.project_dashboard_view, name='project_dashboard'),
    path('sierra_sendoff/', tools.sierra_sendoff_view, name='sierra_sendoff'),      
    path('sierra_sendoff_results/', tools.sierra_sendoff_results, name='sierra_sendoff_results'),      
    path('sierra_searcher/', tools.sierra_searcher_view, name='sierra_searcher'),    

]
