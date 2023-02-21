from django.db import models
from .userModel import User

class UserBankAccounts(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    accountHolderName = models.CharField(max_length = 255)
    accountNumber = models.CharField(max_length=255, null=True, blank=True)
    iban = models.CharField(max_length = 255, null=True, blank=True)
    country = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=255, null=True, blank=True)
    state = models.CharField(max_length = 255, null = True, blank = False)
    postCode = models.IntegerField(null=True, blank=True)
    firstLine = models.CharField(max_length = 255, null=True, blank=True)
    primary = models.BooleanField(default = False)

    class Meta:
        db_table = 'UserBankAccounts'
        indexes = [
            models.Index(fields=['id'])
        ]
    
