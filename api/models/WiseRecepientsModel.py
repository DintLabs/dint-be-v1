from django.db import models
from .userModel import User
from django.utils import timezone
import uuid

class WiseRecepients(models.Model):
    user = models.ForeignKey(User, on_delete = models.CASCADE, null=True, blank=True)
    accountHolderName = models.CharField(max_length = 255)
    accountNumber = models.CharField(max_length=255, null=True, blank=True)
    receipt_id = models.CharField(max_length=255, null=True, blank=True)
    abartn = models.IntegerField()
    country = models.CharField(max_length=255)
    city = models.CharField(max_length=255, null=True, blank=True)
    state = models.CharField(max_length = 255, null = True, blank = False)
    postCode = models.IntegerField()
    firstLine = models.CharField(max_length = 255, null=True, blank=True)
    primary = models.BooleanField(default = False)

    class Meta:
        db_table = 'transferwise_recepients'
        indexes = [
            models.Index(fields=['id'])
        ]