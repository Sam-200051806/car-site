from django.shortcuts import render,get_object_or_404
from .models import Car
from django.core.paginator import Paginator,EmptyPage,PageNotAnInteger
# Create your views here.
def cars(request):
    cars = Car.objects.order_by('-created_date')
    paginator = Paginator(cars,4)
    page = request.GET.get('page')
    paged_cars = paginator.get_page(page)
    model_feilds = Car.objects.values_list('model',flat=True).distinct()
    city_feilds = Car.objects.values_list('city',flat=True).distinct()
    year_feilds = Car.objects.values_list('year',flat=True).distinct()
    body_style_feilds = Car.objects.values_list('body_style',flat=True).distinct()
    data = {
        'cars' : paged_cars,
        'model_feilds' : model_feilds,
        'city_feilds' : city_feilds,
        'year_feilds' : year_feilds,
        'body_style_feilds' : body_style_feilds,
    }
    return render(request,'cars/cars.html',data)

def car_detail(request,id):
    single_car = get_object_or_404(Car,pk = id)
    data = {
        'single_car' : single_car,
    }
    return render(request,'cars/car_detail.html',data)

def search(request):
    cars = Car.objects.order_by('-created_date')
    model_feilds = Car.objects.values_list('model',flat=True).distinct()
    city_feilds = Car.objects.values_list('city',flat=True).distinct()
    year_feilds = Car.objects.values_list('year',flat=True).distinct()
    body_style_feilds = Car.objects.values_list('body_style',flat=True).distinct()
    transmission_feilds = Car.objects.values_list('transmission',flat=True).distinct()
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']
        if keyword:
            cars = cars.filter(description__icontains = keyword)
    if 'model' in request.GET:
        model = request.GET['model']
        if model:
            cars = cars.filter(model__iexact = model)
    if 'city' in request.GET:
        city = request.GET['city']
        if city:
            cars = cars.filter(city__iexact = city)
    if 'year' in request.GET:
        keyword = request.GET['year']
        if keyword:
            cars = cars.filter(year__iexact = keyword)
    if 'body_style' in request.GET:
        keyword = request.GET['body_style']
        if keyword:
            cars = cars.filter(body_style__iexact = keyword)
    if 'min_price' in request.GET:
        min_price = request.GET['min_price']
        max_price = request.GET['max_price']
        if max_price:
           cars = cars.filter(price__gte = min_price,price__lte = max_price)
    if 'transmission' in request.GET:
        transmission = request.GET['transmission']
        if max_price:
           cars = cars.filter(transmission__iexact = transmission)
    data = {
        'cars' : cars,'model_feilds' : model_feilds,
        'city_feilds' : city_feilds,
        'year_feilds' : year_feilds,
        'body_style_feilds' : body_style_feilds,
        'transmission_feilds' : transmission_feilds,
    }
    return render(request,'cars/search.html',data)