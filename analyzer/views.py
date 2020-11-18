from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from .forms import UploadFileForm
from packetstudio import settings
import hashlib
from scapy.all import *
from .utils import PcapAnalyzer
import os

def get_path(file_name):
	if(not os.path.exists(settings.BASE_DIR+os.path.sep+"analyzer"+os.path.sep+"files")):
		os.mkdir(settings.BASE_DIR+os.path.sep+"analyzer"+os.path.sep+"files")
	return settings.BASE_DIR+os.path.sep+"analyzer"+os.path.sep+"files"+os.path.sep+file_name+".cap"

def get_file(file_name):
	return open(get_path(file_name))

# Create your views here.
@login_required(login_url=settings.LOGIN_URL)
def index(request):
	if(request.method == "POST"):
		print(request.FILES)
		# dosyayı yükle
		result = upload_file(request.FILES.get("file",None))
		if(result):
			return redirect("/analyzer/show?fileid={}".format(result))
		else:
			form = UploadFileForm()
			return render(request,"analyzer/index.html",{"form":form})
	else:
		form = UploadFileForm()
		# formu göster
		return render(request,"analyzer/index.html",{"form":form})

def upload_file(f):
	if(not f):
		return False
	try:
		temp = hashlib.md5(str(f).encode("utf-8")).hexdigest()
		dosya_adi = get_path(temp)

		with open(dosya_adi,'wb+') as destination:
			for chunk in f.chunks():
				destination.write(chunk)
		return temp
	except Exception as e:
		print("Hata: {}".format(str(e)))
		return False

@login_required(login_url=settings.LOGIN_URL)
def show(request):
    # Burada analizi yapılan bir PCAP dosyasının
    # sonuçları gösterilecek.
    try:
    	file_id = request.GET.get("fileid")
    	analiz = PcapAnalyzer(get_path(file_id))
    	if(analiz.is_pcap()):
    		# pcap dosyası
    		sonuc = {**analiz.get_protocols_data(),**analiz.get_ip_data()}
    		return render(request,"analyzer/show.html",sonuc)
    	else:
    		# pcap dosyası değil
    		return redirect("/analyzer")
    	
    except Exception as e:
    	return redirect("/analyzer")