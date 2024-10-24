from django.contrib import admin
from .models import Team
# Register your models here.

class Teamadmin(admin.ModelAdmin):
    list_display = ("id","first_name","designation","create_date")
    list_display_links = ("first_name","id")
    search_fields = ("first_name","last_name","designation")
    list_filter = ("designation",)
admin.site.register(Team,Teamadmin)