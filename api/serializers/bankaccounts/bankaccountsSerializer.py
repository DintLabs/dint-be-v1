from dataclasses import field
from rest_framework import serializers
from api.models.BankAccountsModel import UserBankAccounts

from django.core.exceptions import ValidationError

class UserBankAccountsSerializer(serializers.ModelSerializer):
    """
    Return the details of User Bank Accounts.
    """
    class Meta(object):
        many = True
        model = UserBankAccounts
        fields = '__all__'

