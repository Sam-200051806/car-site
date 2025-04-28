from django.contrib import admin 
from django.urls import path 
from django.conf.urls.static import static
from django.conf import settings
from . import views
urlpatterns = [
    path('', views.home , name='home'),
    path('about' , views.about , name = 'about'),
    path('services' , views.services , name = 'services'),
    path('contact' , views.contact , name = 'contact'),
    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    path('data-deletion/', views.data_deletion, name='data_deletion'),
]