from django.db import models
from .userModel import User
from django.utils import timezone

class WiseQuotes(models.Model):
    user = models.ForeignKey(User, on_delete = models.CASCADE, null=True, blank=True)
    sourceCurrency = models.CharField(max_length = 20, null=True, blank=True)
    targetCurrency = models.CharField(max_length = 20, null=True, blank=True)
    sourceAmount = models.CharField(max_length=250, null=True, blank=True)
    quote_id = models.CharField(max_length=250, null=True, blank=True)
    guid = models.CharField(max_length = 250, null=True, blank=True)
  
    class Meta:
        db_table = 'transferwise_quotes'
        indexes = [
            models.Index(fields=['id'])
        ]