from django.urls import path
from django.conf.urls import include
from . import views

urlpatterns = [
    path("login/",views.index),
    path("logout/",views.log_out),
    
]
