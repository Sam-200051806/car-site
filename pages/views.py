from django.shortcuts import render,redirect
from .models import Team
from cars.models import Car
from django.contrib import messages

# Create your views here.
from django.contrib.auth.models import User

from django.core.mail import send_mail

def home(request):
    teams = Team.objects.all()
    featured_car = Car.objects.order_by('-created_date').filter(is_featured = True)
    all_cars = Car.objects.order_by("-created_date")
    # search_feilds = Car.objects.values('model','year','city','body_style')
    model_feilds = Car.objects.values_list('model',flat=True).distinct()
    city_feilds = Car.objects.values_list('city',flat=True).distinct()
    year_feilds = Car.objects.values_list('year',flat=True).distinct()
    body_style_feilds = Car.objects.values_list('body_style',flat=True).distinct()
    data = {
        'teams' : teams,
        'featured_car' : featured_car,
        'all_cars' : all_cars,
        'city_feilds' : city_feilds,
        'model_feilds' : model_feilds,
        'year_feilds' : year_feilds,
        'body_style_feilds' : body_style_feilds,
    }
    return render(request,'pages/home.html',data)

def about(request):
    teams = Team.objects.all()
    data = {
        'teams' : teams,
    }
    return render(request,'pages/about.html',data)

def services(request):
    return render(request,'pages/services.html')

def contact(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        subject = request.POST['subject']
        phone = request.POST['phone']
        message = request.POST['message']

        # Email to admin
        email_subject = "You have a new message from Carzone website regarding " + subject
        message_body = 'Name: ' + name + ', Email: ' + email + ', Phone: ' + phone + ', Message: ' + message
        admin_info = User.objects.get(is_superuser = True)
        admin_email = admin_info.email
        send_mail(
            email_subject,
            message_body,
            "carzone1806@gmail.com",
            [admin_email],
            fail_silently=False,
        )

        user_email_subject = "Your Contact Request - Carzone"
        user_email_message = f"""
Hello {name},

Thank you for contacting Carzone regarding "{subject}".

We have received your message and our team will review it shortly. Here's a summary of your contact request:

Subject: {subject}
Message: {message}

We appreciate your interest and will get back to you as soon as possible.

Thank you for choosing Carzone!

Best regards,
The Carzone Team
        """

        send_mail(
            user_email_subject,
            user_email_message,
            "carzone1806@gmail.com",
            [email],
            fail_silently=False,
        )

        messages.success(request,"Thank you for contacting us. We will get back to you very shortly. A confirmation email has been sent to your email address.")
        return redirect('contact')
    return render(request,'pages/contact.html')

def privacy_policy(request):
    return render(request, 'pages/privacy_policy.html')

def data_deletion(request):
    return render(request, 'pages/data_deletion.html')