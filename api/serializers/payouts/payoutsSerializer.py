from dataclasses import field
from rest_framework import serializers
from api.models.PayoutsModel import Payouts

from django.core.exceptions import ValidationError

class UserPayoutsSerializer(serializers.ModelSerializer):
    """
    Return the details of User Requested Payouts
    """
    class Meta(object):
        many = True
        model = Payouts
        fields = '__all__'

