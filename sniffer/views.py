from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from packetstudio import settings
import os

@login_required(login_url=settings.LOGIN_URL)
def index(request):
    return render(request,'sniffer/index.html')

@login_required(login_url=settings.LOGIN_URL)
def download(request,dosya_adi):
	dizin = os.path.join(st.BASE_DIR,"sniffer","download",dosya_adi)
	if(os.path.exists(dizin)):	
		response = HttpResponse(open(dizin,'rb').read())
		response['Content-Type'] = 'application/cap'
		response['Content-Disposition'] = 'attachment; filename={}'.format(dosya_adi)
		os.remove(dizin)
		return response
	else:
		return redirect("/sniffer")
