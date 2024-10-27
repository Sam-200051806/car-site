from django.contrib import admin
from .models import Car
# Register your models here.
class CarAdmin(admin.ModelAdmin):
    list_display = ('id','car_title','city','color','year','body_style','fuel_type','is_featured')
    list_display_links = ('id','car_title')
    list_editable = ('is_featured',)
    search_fields = ('id','car_title','fuel_type','is_featured')
    list_filter = ('city' ,'body_style' ,'model','fuel_type')
admin.site.register(Car,CarAdmin)