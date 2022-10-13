from operator import mod
from statistics import mode
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords
from .userModel import User
from .postsModel import *


class UserSubscriptionTier(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='user_tier', on_delete=models.DO_NOTHING, null=True, blank=True)
    page = models.ForeignKey(Page, related_name='subscription_tier_page', on_delete=models.DO_NOTHING, null=True, blank=True)
    tier_name = models.CharField(max_length=100, null=True, blank=True)
    price = models.FloatField(null=True, blank=True)
    validity_in_months = models.CharField(max_length=10, null=True, blank=True)
    discount = models.CharField(max_length=10, null=True, blank=True)
    final_price = models.FloatField(null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='user_subscription_tier_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'user_subscription_tier'
        indexes = [
            models.Index(fields=['id'])
        ]
