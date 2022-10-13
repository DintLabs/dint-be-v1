from django.db import models
from django.contrib.auth import get_user_model
# Create your models here.

User = get_user_model()


class CreditCard(models.Model):
    country = models.CharField(max_length=32)
    state = models.CharField(max_length=32)
    street = models.TextField()
    city = models.CharField(max_length=32)
    zip_code = models.CharField(max_length=16)
    email = models.EmailField()
    card_name = models.CharField(max_length=32, default='')
    card_token = models.CharField(max_length=56)
    card_type = models.CharField(max_length=32, default='')
    fund = models.IntegerField(default=0)
    card_number = models.IntegerField(default=0)
    customer_id = models.CharField(max_length=48, default='')
    card_id = models.CharField(max_length=48, default='')
    default_card = models.BooleanField(default=False)
    card_expired = models.CharField(max_length=16, default='')
    is_activate = models.BooleanField(default=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
