from django.urls import re_path

from . import consumers

sniffer_urlpatterns = [
    re_path(r'sniffer/$', consumers.SniffConsumer),
]