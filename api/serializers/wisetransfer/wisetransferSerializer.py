from rest_framework import serializers
from django.core.exceptions import ValidationError
from api.models import WiseRecepients, WiseQuotes, WisePayments

class WiseQuotesSerializer(serializers.ModelSerializer):

    class Meta:
        model = WiseQuotes
        fields = "__all__"
        
class WiseRecepientsSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = WiseRecepients
        fields = "__all__"

class WisePaymentsSerializer(serializers.ModelSerializer):

    class Meta:
        model = WisePayments
        fields = "__all__"