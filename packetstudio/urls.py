from django.contrib import admin
from django.urls import path
from django.conf.urls import include
from . import views

urlpatterns = [
    path("sniffer/",include("sniffer.urls")),
    path("analyzer/",include("analyzer.urls")),
    path("help/",views.help),
    path("loginmanager/",include("login_manager.urls")),
    path("admin/", admin.site.urls),
    path("",views.index,name="index"),
]
