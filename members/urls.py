from django.urls import path
from . import views

urlpatterns = [
    path('login_user', views.login_user, name="login"),
    path('invalid_user', views.invalid_user, name="invalid_login"),
    #path('create_user', views.create_user, name="create_user"),
    path('logout_user', views.logout_user, name="logout")
]