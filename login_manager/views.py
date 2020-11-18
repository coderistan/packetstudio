from django.shortcuts import render,redirect
from django.contrib.auth import login,logout
from django.contrib.auth.forms import AuthenticationForm
from packetstudio import settings

# Create your views here.
def index(request):
    if request.user.is_authenticated:
        print("zaten giriş yapılmış")
        return redirect("/")

    if request.method == "POST":
        path = request.POST.get("redirect")
        path = path if path else "/"

        login_form = AuthenticationForm(request,data=request.POST)
        if login_form.is_valid():
            login(request,login_form.get_user())
            print("PATH",path)
            return redirect(path)
        else:
            return render(request,"login_manager/index.html",{"path":path})
        
    else:
        return render(request,"login_manager/index.html",{})

def log_out(request):
    if request.user.is_authenticated:
        logout(request)
        return redirect("/")
    else:
        return redirect(settings.LOGIN_URL)