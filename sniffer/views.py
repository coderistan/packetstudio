from django.shortcuts import render,redirect
from django.http import HttpResponse
from packetstudio import settings as st
import os

def index(request):
    return render(request,'sniffer/index.html')

def download(request,dosya_adi):
	dizin = os.path.join(st.BASE_DIR,"sniffer","download",dosya_adi)
	if(os.path.exists(dizin)):	
		response = HttpResponse(open(dizin,'rb').read())
		response['Content-Type'] = 'application/cap'
		response['Content-Disposition'] = 'attachment; filename={}'.format(dosya_adi)
		return response
	else:
		return redirect("/sniffer")