from cryptography.fernet import Fernet
from django.contrib import admin
from .models import *

# Register your models here.
# admin.site.register(User)


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'user_wallet_address')

    def user_wallet_address(self, user):
        if not user.wallet_address:
            return
        receiver_wallet = user.wallet_address

        receiver_wallet_bytes = bytes(receiver_wallet)
        key = Fernet(settings.ENCRYPTION_KEY)
        receiver_decwallet = key.decrypt(receiver_wallet_bytes).decode()
        return receiver_decwallet