from django.contrib import admin

from .models import *


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'user_wallet_address')
    readonly_fields = ['wallet_address']

    def get_object(self, request, object_id, from_field=None):
        object = super().get_object(request, object_id, from_field)

        if request.method == 'GET':
            object.wallet_address = object.decrypted_wallet_address
        return object

    def user_wallet_address(self, user: User):
        return user.decrypted_wallet_address
