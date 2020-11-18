from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from packetstudio import settings

@login_required(login_url=settings.LOGIN_URL)
def index(request):
    return render(request,"main/index.html",{})

@login_required(login_url=settings.LOGIN_URL)
def help(request):
    return render(request,"main/help.html",{})