from django.urls import path
from . import views
from map.views import map_view, getConfigDiff
from members.views import login_user

# URLConf module
urlpatterns =  [
    path('/map/', views.map),
    path('/getConfigDiff/', getConfigDiff, name='getConfigDiff'),
    path('login/', views.login_user, name='login_user'),
]