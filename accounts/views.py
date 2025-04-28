from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib import auth
from contacts.models import Contact
from django.contrib.auth.decorators import login_required
import os
from dotenv import load_dotenv
load_dotenv()
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
@login_required(login_url = 'login')
def dashboard(request):
    user_inquiry = Contact.objects.order_by('-create_date').filter(user_id = request.user.id)
    data  = {
        'inquiries' : user_inquiry,
    }
    return render(request, 'accounts/dashboard.html',data)

def twitter_login(request):
    """Custom Twitter login view to bypass the MultipleObjectsReturned error"""
    from allauth.socialaccount.models import SocialApp
    from allauth.socialaccount.providers.oauth2.client import OAuth2Client
    from django.shortcuts import redirect
    from django.urls import reverse
    from django.conf import settings
    import requests
    
    try:
        # Get the first Twitter app
        app = SocialApp.objects.filter(provider='twitter').first()
        
        if not app:
            messages.error(request, "Twitter authentication is not configured")
            return redirect('login')
            
        # Create OAuth2 parameters
        redirect_uri = request.build_absolute_uri(reverse('accounts:twitter_callback'))
        
        # Twitter OAuth 2.0 authorization URL
        auth_url = 'https://twitter.com/i/oauth2/authorize'
        
        # Required parameters
        params = {
            'client_id': os.getenv('CLIENT_ID'),
            'redirect_uri' : request.build_absolute_uri(reverse('accounts:twitter_callback')),
            'response_type': 'code',
            'scope': 'tweet.read users.read offline.access',
            'state': request.session.session_key or 'random-state',
            'code_challenge': 'challenge',  # In production, use PKCE properly
            'code_challenge_method': 'plain'
        }
        
        # Build the authorization URL
        auth_url = f"{auth_url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
        
        # Store state in session for validation on callback
        request.session['twitter_oauth_state'] = params['state']
        
        # Redirect to Twitter authorization page
        return redirect(auth_url)
        
    except Exception as e:
        messages.error(request, f"Error connecting to Twitter: {str(e)}")
        return redirect('login')
    


def twitter_callback(request):
    """Handle the callback from Twitter OAuth"""
    from allauth.socialaccount.models import SocialApp
    import requests
    
    try:
        # Get authorization code from callback
        code = request.GET.get('code')
        state = request.GET.get('state')
        
        # Verify state to prevent CSRF
        if state != request.session.get('twitter_oauth_state'):
            messages.error(request, "Invalid OAuth state")
            return redirect('login')
            
        # Get the Twitter app
        app = SocialApp.objects.filter(provider='twitter').first()
        
        # Exchange the code for an access token
        token_url = 'https://api.twitter.com/2/oauth2/token'
        redirect_uri = request.build_absolute_uri(reverse('accounts:twitter_callback'))
        
        # Prepare token request
        token_data = {
            'client_id': app.client_id,
            'client_secret': app.secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
            'code_verifier': 'challenge'  # In production, use PKCE properly
        }
        
        # Get access token
        response = requests.post(token_url, data=token_data)
        token_json = response.json()
        
        if 'access_token' not in token_json:
            messages.error(request, "Failed to obtain access token")
            return redirect('login')
            
        # Get user information
        user_url = 'https://api.twitter.com/2/users/me'
        headers = {'Authorization': f'Bearer {token_json["access_token"]}'}
        user_response = requests.get(user_url, headers=headers)
        user_json = user_response.json()
        
        # Now you have the user information, you can:
        # 1. Create or get a user in your system
        # 2. Log them in
        # 3. Redirect to dashboard
        
        # For now, just redirect to dashboard (you'll need to implement the login part)
        messages.success(request, "Successfully logged in with Twitter")
        return redirect('dashboard')
        
    except Exception as e:
        messages.error(request, f"Error processing Twitter callback: {str(e)}")
        return redirect('login')