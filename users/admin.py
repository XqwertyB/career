from django.contrib import admin

from users.models import User, UserConfirmation
from config.models import UserData


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id','first_name', 'last_name', 'phone_number', 'is_staff', 'is_active', 'auth_status', 'role']
    search_fields = ['first_name', 'last_name', 'phone_number']


@admin.register(UserConfirmation)
class UserConfirmationAdmin(admin.ModelAdmin):
    list_display = ['code', 'user', 'expiration_time', 'is_confirmed']
    search_fields = ['user__name', 'code']

@admin.register(UserData)
class UserDataAdmin(admin.ModelAdmin):
    pass