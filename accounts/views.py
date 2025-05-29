from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib import auth
from contacts.models import Contact
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings
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
            return redirect('accounts:dashboard')
        else:
            messages.error(request, "Invalid login credentials.")
            return redirect('accounts:login')
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
                return redirect('accounts:register')
            elif User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists')
                return redirect('accounts:register')
            else:
                user = User.objects.create_user(
                    username=username,
                    password=password,
                    email=email,
                    first_name=firstname,
                    last_name=lastname
                )

                user = auth.authenticate(username=username, password=password)
                auth.login(request, user)

                messages.success(request, "You are now logged in.")
                return redirect('accounts:dashboard')
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('accounts:register')
    else:
        return render(request, 'accounts/register.html')

def logout(request):
    if request.method == "POST":
        auth.logout(request)
        messages.success(request, "You have been logged out.")
        return redirect('home')
    return redirect('home')
@login_required(login_url='accounts:login')
def dashboard(request):
    user_inquiry = Contact.objects.order_by('-create_date').filter(user_id = request.user.id)
    data  = {
        'inquiries' : user_inquiry,
    }
    return render(request, 'accounts/dashboard.html',data)

def twitter_login(request):
    """Custom Twitter login view to bypass the MultipleObjectsReturned error"""
    from allauth.socialaccount.models import SocialApp
    import requests
    import base64
    import hashlib
    import secrets

    try:
        # Get the first Twitter app
        app = SocialApp.objects.filter(provider='twitter').first()

        if not app:
            messages.error(request, "Twitter authentication is not configured")
            return redirect('accounts:login')

        # Create proper PKCE code verifier and challenge
        code_verifier = secrets.token_urlsafe(64)[:128]
        code_verifier_bytes = code_verifier.encode('ascii')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier_bytes).digest()
        ).decode('ascii').rstrip('=')

        # Store code_verifier in session for later use in callback
        request.session['twitter_code_verifier'] = code_verifier

        # Create OAuth2 parameters
        redirect_uri = request.build_absolute_uri(reverse('accounts:twitter_callback'))

        # Twitter OAuth 2.0 authorization URL
        auth_url = 'https://twitter.com/i/oauth2/authorize'

        # Required parameters
        params = {
            'client_id': app.client_id,  # Use app.client_id instead of env variable
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'tweet.read users.read offline.access',
            'state': secrets.token_urlsafe(32),  # Better state value
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'  # Use S256 instead of plain
        }

        # Store state in session for validation on callback
        request.session['twitter_oauth_state'] = params['state']

        # Build the authorization URL
        auth_url = f"{auth_url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"

        # Redirect to Twitter authorization page
        return redirect(auth_url)

    except Exception as e:
        messages.error(request, f"Error connecting to Twitter: {str(e)}")
        return redirect('accounts:login')



def twitter_callback(request):
    """Handle the callback from Twitter OAuth"""
    from allauth.socialaccount.models import SocialApp, SocialAccount, SocialLogin
    from django.contrib.auth import login
    from django.contrib.auth.models import User
    import requests

    try:
        # Get authorization code from callback
        code = request.GET.get('code')
        state = request.GET.get('state')

        # Verify state to prevent CSRF
        if state != request.session.get('twitter_oauth_state'):
            messages.error(request, "Invalid OAuth state")
            return redirect('accounts:login')

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
            'code_verifier': request.session.get('twitter_code_verifier')  # Use stored code_verifier
        }

        # Get access token
        response = requests.post(token_url, data=token_data)
        token_json = response.json()

        if 'access_token' not in token_json:
            messages.error(request, "Failed to obtain access token")
            return redirect('accounts:login')

        # Get user information
        user_url = 'https://api.twitter.com/2/users/me'
        headers = {'Authorization': f'Bearer {token_json["access_token"]}'}
        user_response = requests.get(user_url, headers=headers)
        user_json = user_response.json()

        # Log the user information for debugging
        print("Twitter user data:", user_json)

        # Get or create user based on Twitter ID
        twitter_id = user_json['data']['id']
        twitter_username = user_json['data']['username']

        # Check if social account exists
        social_account = SocialAccount.objects.filter(provider='twitter', uid=twitter_id).first()

        if social_account:
            # If social account exists, log the user in
            user = social_account.user
        else:
            # Create a new user
            user_email = f"{twitter_username}@twitter.com"  # placeholder email
            username = f"twitter_{twitter_username}"

            # Check if username exists
            if User.objects.filter(username=username).exists():
                username = f"{username}_{twitter_id}"

            # Create user
            user = User.objects.create_user(
                username=username,
                email=user_email,
                password=None  # Set unusable password
            )
            user.set_unusable_password()
            user.save()

            # Create social account
            social_account = SocialAccount.objects.create(
                user=user,
                provider='twitter',
                uid=twitter_id,
                extra_data=user_json['data']
            )

        # Log the user in
        login(request, user)
        messages.success(request, "Successfully logged in with Twitter")
        return redirect('accounts:dashboard')

    except Exception as e:
        messages.error(request, f"Error processing Twitter callback: {str(e)}")
        return redirect('accounts:login')

def forgot_password(request):
    """Handle forgot password requests"""
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            # Generate password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Build reset URL
            reset_url = request.build_absolute_uri(
                reverse('accounts:reset_password', kwargs={'uidb64': uid, 'token': token})
            )

            # Prepare email context
            context = {
                'user': user,
                'reset_url': reset_url,
            }

            # Render email template
            html_message = render_to_string('accounts/password_reset_email.html', context)
            plain_message = strip_tags(html_message)

            # Send email
            send_mail(
                subject='Password Reset - Carzone',
                message=plain_message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[email],
                html_message=html_message,
                fail_silently=False,
            )

            messages.success(request, 'Password reset link has been sent to your email address.')
            return redirect('accounts:login')

        except User.DoesNotExist:
            # Don't reveal that the email doesn't exist for security reasons
            messages.success(request, 'If an account with that email exists, a password reset link has been sent.')
            return redirect('accounts:login')
        except Exception as e:
            messages.error(request, 'An error occurred while sending the reset email. Please try again.')
            return redirect('accounts:forgot_password')

    return render(request, 'accounts/forgot_password.html')

def reset_password(request, uidb64, token):
    """Handle password reset with token"""
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password == confirm_password:
                # Validate password strength
                if len(new_password) < 8:
                    messages.error(request, 'Password must be at least 8 characters long.')
                    return render(request, 'accounts/reset_password.html')

                # Set new password
                user.set_password(new_password)
                user.save()

                messages.success(request, 'Your password has been successfully reset. You can now login with your new password.')
                return redirect('accounts:login')
            else:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'accounts/reset_password.html')

        return render(request, 'accounts/reset_password.html')
    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        return redirect('accounts:forgot_password')