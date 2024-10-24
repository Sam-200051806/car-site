from django.db import models

# Create your models here.
class Car(models.Model):
    car_title = models.CharField(max_length=255)
    # state = m