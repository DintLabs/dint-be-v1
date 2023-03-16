from django.db import models
from .userModel import User
from django.utils import timezone

class Payouts(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    accountHolderName = models.CharField(max_length = 255, null=True)
    accountNumber = models.CharField(max_length=255, null=True, blank=True)
    amount = models.IntegerField()
    country = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=255, null=True, blank=True)
    state = models.CharField(max_length = 255, null = True, blank = False)
    postCode = models.IntegerField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    paid = models.BooleanField(default=False)

    class Meta:
        db_table = 'UserPayouts'
        indexes = [
            models.Index(fields=['id'])
        ]
    