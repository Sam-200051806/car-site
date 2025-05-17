from django.shortcuts import render,redirect
from .models import Contact
from django.contrib import messages
from django.core.mail import send_mail
from django.contrib.auth.models import User
# Create your views here.
def inquiry(request):
    if request.method == "POST":
        car_id = request.POST['car_id']
        car_title = request.POST['car_title']
        user_id = request.POST['user_id']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        customer_need = request.POST['customer_need']
        city = request.POST['city']
        state = request.POST['state']
        email = request.POST['email']
        phone = request.POST['phone']
        message = request.POST['message']
        if request.user.is_authenticated:
            user_i = request.user.id
            has_contacted = Contact.objects.all().filter(car_id = car_id,user_id = user_i)
            if has_contacted:
                messages.error(request,"you have already made an enquiry about this car . please wait until we gae back to you !")
                return redirect('/cars/' + car_id)


        contact = Contact(car_id = car_id,car_title = car_title,user_id = user_id,first_name = first_name,last_name= last_name,customer_need = customer_need,city = city,state = state,email = email,phone = phone,message = message)
        admin_info = User.objects.get(is_superuser = True)
        admin_email = admin_info.email

        # Email to admin
        send_mail(
            "New Car Inquiry",
            "You have a new inquiry for the car " + car_title + ". Please login to the admin panel for more info.",
            "carzone1806@gmail.com",
            [admin_email],
            fail_silently=False,
        )

        user_email_subject = "Your Car Inquiry - " + car_title
        user_email_message = f"""
Hello {first_name} {last_name},

Thank you for your inquiry about the {car_title}.

Here's a summary of your inquiry:
- Car: {car_title}
- Your Need: {customer_need}
- Message: {message}

Our team will review your inquiry and get back to you as soon as possible.

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

        contact.save()
        messages.success(request,"Your request has been submitted, we will get back to you shortly. A confirmation email has been sent to your email address.")
        return redirect('/cars/' + car_id)