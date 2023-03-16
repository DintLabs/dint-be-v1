from django.contrib import admin
from .models import *
from api.models.userModel import User, UserReferralWallet
from dint import settings
# Register your models here.
from cryptography.fernet import Fernet

class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'user_wallet_decrypted', 'user_referred_wallet')

    def user_wallet_decrypted(self, obj):
        try:
            user_obj = User.objects.get(email = obj)
            user_enc_wallet = user_obj.wallet_address
            key = Fernet(settings.ENCRYPTION_KEY)
            wallet_bytes = bytes(user_enc_wallet)
            referral_decwallet = key.decrypt(wallet_bytes).decode()
            address = referral_decwallet
            return address
        except:
            pass


    def user_referred_wallet(self, obj):
        try:
            user_referral_wallet = UserReferralWallet.objects.filter(user_referral = obj)
            if user_referral_wallet:
                referral_obj = UserReferralWallet.objects.get(user_referral = obj)
                referred_user = referral_obj.referred_by
                referred_user = User.objects.get(email = referred_user)
                enc_wallet = referred_user.wallet_address
                key = Fernet(settings.ENCRYPTION_KEY)
                wallet_bytes = bytes(enc_wallet)
                referral_decwallet = key.decrypt(wallet_bytes).decode()
                return referral_decwallet
        except Exception as e:
            pass

admin.site.register(User, UserAdmin)


