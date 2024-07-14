from __future__ import absolute_import, unicode_literals

import os 

from celery import Celery

from celery.schedules import crontab

from datetime import datetime

from django.conf import settings
from kombu import Exchange, Queue

timezone = 'PST'

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dash.settings')

import os

CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'default_broker_url')


app = Celery('dash')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()

from celery.signals import setup_logging
@setup_logging.connect
def configure_logging(**kwargs):
    from logging.config import dictConfig
    dictConfig(settings.LOGGING)

app.conf.task_queues = (
    Queue('ping_devices_queue', Exchange('ping_devices_queue'), routing_key='ping_devices'),
    Queue('configure_devices_queue', Exchange('configure_devices_queue'), routing_key='configure_devices'),
    Queue('get_info_queue', Exchange('get_info_queue'), routing_key='get_info_server'),
    Queue('api_queue', Exchange('api_queue'), routing_key='api_server'),
)

app.conf.task_routes = {
    'map.tasks.ping_devices_task': {'queue': 'ping_devices_queue'},
    'map.tasks.ping_license_server': {'queue': 'ping_devices_queue'},
    'map.tasks.cycle_port_task': {'queue': 'configure_devices_queue'},
    'map.tasks.update_port_info': {'queue': 'configure_devices_queue'},
    'map.tasks.set_interface': {'queue': 'configure_devices_queue'},
    'map.tasks.set_l2interface': {'queue': 'configure_devices_queue'},
    'map.tasks.set_l3interface': {'queue': 'configure_devices_queue'},
    'map.tasks.push_startup_configs': {'queue': 'configure_devices_queue'},
    'map.tasks.gather_startup_configs': {'queue': 'get_info_queue'},
    'map.tasks.gather_running_configs': {'queue': 'get_info_queue'},
    'map.tasks.clean_artifacts': {'queue': 'configure_devices_queue'},
    'map.tasks.get_device_info': {'queue': 'get_info_queue'},
    'map.tasks.github_pull': {'queue': 'get_info_queue'},
    'map.tasks.update_host_file_task': {'queue': 'configure_devices_queue'},
    'map.tasks.setup_network_devices': {'queue': 'configure_devices_queue'},
    'map.tasks.update_device': {'queue': 'configure_devices_queue'},
    'map.tasks.setup_github_repo': {'queue': 'api_queue'},
    'map.tasks.sync_ldap': {'queue': 'configure_devices_queue'},
    'map.tasks.create_org_api': {'queue': 'api_queue'},
    'map.tasks.send_logs': {'queue': 'api_queue'},
    'map.tasks.check_date': {'queue': 'get_info_queue'},
}
app.conf.beat_schedule = {
        'clean-up': {
        'task': 'map.tasks.clean_up',
        'schedule': crontab(day_of_month='1-31/90'),
    },
    'update_host_file_task': {
        'task': 'map.tasks.update_host_file_task',  
        'schedule': crontab(minute='*/30'),
    },
    'update-device-info': {
        'task': 'map.tasks.get_device_info',
        'schedule': crontab(minute=0, hour='*/1'),
    },
   'update-port-info': {
       'task': 'map.tasks.update_port_info',
       'schedule': crontab(minute='*/5'),
   },
   'ping_license_server': {
       'task': 'map.tasks.ping_license_server',
       'schedule': crontab(minute='*/2'),
   },
    'gather-running-config': {
        'task': 'map.tasks.gather_running_configs',
        'schedule': crontab(minute=0, hour='*/4'),
    },
    'send-logs': {
        'task': 'map.tasks.send_logs',
        'schedule': crontab(minute=0, hour=5),
    },
    'github-pull': {
        'task': 'map.tasks.github_pull',
        'schedule': crontab(minute=0, hour='*/3'),
    },
        'ping_devices_task': {
        'task': 'map.tasks.ping_devices_task',
        'schedule': crontab(minute='*/2'),
    },
    'clean_artifacts': {
        'task': 'map.tasks.clean_artifacts',
        'schedule': crontab(minute=0, hour=5),
    },
    'sync_ldap': {
        'task': 'map.tasks.sync_ldap',
        'schedule': crontab(minute=0, hour='*/2'),
    },
    'check_date_every_8_hours': {
        'task': 'map.tasks.check_date',
        'schedule': crontab(minute=0, hour='*/8'), 
    },

}
    #'clean-up': {
    #'task': 'map.tasks.clean_up',
    #'schedule': crontab(minute='30', hour='2'),

    #'update-vlan-info': {
    #    'task': 'map.tasks.update_vlan_info_task',  
    #    'schedule': crontab(minute='*/60'),
    #},
    #'update-device-info': {
    #    'task': 'map.tasks.update_device_info_task',
    #    'schedule': crontab(minute='*/20'),
    #},
    ### RUN THIS THRID IT GETS WEBEX IDS
    #'get_webex_id': {
    #    'task': 'map.tasks.get_webex_id',
    #    'schedule': crontab(minute='15', hour='9'),
    #},
    ### RUN THIS FIRST IT GRABS ALL USERS IN AZURE
    #'get_user_list': {
    #    'task': 'map.tasks.get_user_list',
    #    'schedule': crontab(minute='00', hour='9'),
    #},
    #'get_webex_token': {
    #    'task': 'map.tasks.get_webex_token',
    #    'schedule': crontab(minute='0',hour='0', day_of_week='sun'),
    #},
    ### RUN THIS SECOND IT GRABS ALL UPNS IN AZURE
    #'get_user_info': {
    #    'task': 'map.tasks.get_user_info',
    #    'schedule': crontab(minute='10', hour='9'),
    #},
    ### RUN THIS 4TH IT GRABS LICENSES
    #'get_webex_info':{
    #    'task': 'map.tasks.get_webex_info',
    #    'schedule': crontab(minute='20', hour='9')
    #},
    ### RUN THIS 5Th
    #'get_webex_dev_id':{
    #    'task': 'map.tasks.get_webex_dev_id',
    #    'schedule': crontab(minute='30', hour='9')
    #},
    #'delete_dev_id':{
    #    'task': 'map.tasks.delete_dev_id',
    #    'schedule': crontab(minute='43')
    #}
