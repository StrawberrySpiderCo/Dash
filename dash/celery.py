from __future__ import absolute_import, unicode_literals

import os 

from celery import Celery

from celery.schedules import crontab

from datetime import datetime

timezone = 'PST'

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dash.settings')

app = Celery('dash')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()

app.conf.task_queues = {
    'ping_devices_queue': {
        'exchange': 'ping_devices_queue',
        'exchange_type': 'direct',
        'binding_key': 'ping_devices',
    },
    'configure_devices_queue': {
        'exchange': 'configure_devices_queue',
        'exchange_type': 'direct',
        'binding_key': 'configure_devices',
    },
    'get_info_queue': {
        'exchange': 'get_info_queue',
        'exchange_type': 'direct',
        'binding_key': 'get_info_server',
    },
}

app.conf.task_routes = {
    'map.tasks.ping_devices_task': {'queue': 'ping_devices_queue'},
    'map.tasks.configure_devices_task': {'queue': 'configure_devices_queue'},
    'map.tasks.get_info_task': {'queue': 'get_info_queue'},
}

app.conf.beat_schedule = {
        'clean-up': {
        'task': 'map.tasks.clean_up',
        'schedule': crontab(day_of_month='*/30'),
    },
    'update_host_file': {
        'task': 'map.tasks.update_host_file',  
        'schedule': crontab(minute='*/30'),
    },
    'update-device-info': {
        'task': 'map.tasks.get_device_info',
        'schedule': crontab(day_of_week=0, hour=3),
    },
   'update-port-info': {
       'task': 'map.tasks.update_port_info',
       'schedule': crontab(minute='*/20'),
   },
    'gather-running-config': {
        'task': 'map.gather_running_configs',
        'schedule': crontab(hour=4),
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
