from rest_framework import serializers

from api.payments.models import CreditCard


class CreditCardSerializer(serializers.Serializer):
    country = serializers.CharField(max_length=32)
    state = serializers.CharField(max_length=32)
    street = serializers.CharField(max_length=128)
    city = serializers.CharField(max_length=32)
    card_name = serializers.CharField(max_length=32)
    zip_code = serializers.CharField(max_length=16)
    email = serializers.EmailField()
    card_number = serializers.CharField(max_length=16)
    exp_month = serializers.IntegerField()
    exp_year = serializers.IntegerField()
    cvc = serializers.IntegerField()


class CreditCardModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = CreditCard
        exclude = ['created_at', 'updated_at', 'user' ]
