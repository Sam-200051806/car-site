from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib import auth

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['Password']
        user = auth.authenticate(username=username, password=password)
        
        if user is not None:
            auth.login(request, user)
            messages.success(request, "Successfully logged in.")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid login credentials.")
            return redirect('login')
    return render(request, 'accounts/login.html')

def register(request):
    if request.method == 'POST':
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password == confirm_password:
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists')
                return redirect('register')
            elif User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists')
                return redirect('register')
            else:
                user = User.objects.create_user(
                    username=username,
                    password=password,
                    email=email,
                    first_name=firstname,
                    last_name=lastname
                )
                auth.login(request, user)
                messages.success(request, "You are now logged in.")
                return redirect('dashboard')
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')
    else:
        return render(request, 'accounts/register.html')

def logout(request):
    if request.method == "POST":
        auth.logout(request)
        messages.success(request, "You have been logged out.")
        return redirect('home')
    return redirect('home')

def dashboard(request):
    return render(request, 'accounts/dashboard.html')
