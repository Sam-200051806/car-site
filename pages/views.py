from django.shortcuts import render
from .models import Team
from cars.models import Car
# Create your views here.
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
    return render(request,'pages/contact.html')