from django.db import models
from .userModel import User
from django.utils import timezone

class WisePayments(models.Model):
    user = models.ForeignKey(User, on_delete = models.CASCADE, null=True, blank=True)
    profile_id = models.CharField(max_length = 55)
    transfer_id = models.CharField(max_length = 55, null=True, blank=True)
    quote_id = models.CharField(max_length=250, null=True, blank=True)
    quote_uuid = models.CharField(max_length=250, null=True, blank=True)
    customerTransactionId = models.CharField(max_length=250 , null=True, blank = True)
    receipt_id = models.CharField(max_length = 55, null=True, blank=True)
    transferPurpose = models.TextField(null = True, blank = True)

    def __str__(self):
        return str(self.user)

    class Meta:
        db_table = 'transferwise_payments'
        indexes = [
            models.Index(fields=['id'])
        ]