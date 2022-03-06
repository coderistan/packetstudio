# mysite/routing.py
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from sniffer import consumers
from django.conf.urls import url

application = ProtocolTypeRouter({
    'websocket': AuthMiddlewareStack(
        URLRouter([
            url(r"^sniffer/$",consumers.SniffConsumer.as_asgi()),
        ])
    ),
})