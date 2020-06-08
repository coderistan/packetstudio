from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('download/<str:dosya_adi>', views.download, name="download")
]