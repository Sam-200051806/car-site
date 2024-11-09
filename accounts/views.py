from django.shortcuts import render,redirect
from django.contrib import messages
from django.contrib.auth.models import User
# Create your views here.
def login(request):
    return render(request,'accounts/login.html')

def register(request):
    # if request.method == 'POST':
    #     messages.error(request,'This is error message')
    firstname = request.POST['firstname']
    lastname = request.POST['lastname']
    username = request.POST['username']
    email = request.POST['email']
    password = request.POST['password']
    confirm_password = request.POST['confirm_password']
    if password == confirm_password:
        if User.objects.filter(username = username).exists():
            messages.error(request,'User name already exists')
        else:
            if User.objects.filter(email = email).exists():
                messages.error(request,'email already exixts')
                return redirect('register')
            else:
                user = User.objects.create_user(firstname = firstname,lastname = lastname,username=username,password=password)
                user.save()
                messages.success(request,'You are registered successfully')
    else:
        messages.error(request,'Password doesn\'t matches')
        return redirect('register')
    # else:
    #     return render(request,'accounts/register.html')
        
def logout(request):
    return redirect('home')
def dashboard(request):
    return render(request,'accounts/dashboard.html')
    