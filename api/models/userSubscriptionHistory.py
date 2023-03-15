from contextlib import nullcontext
from hashlib import blake2b
from operator import mod
from statistics import mode
from tokenize import blank_re
from django.db import models
from django.utils import timezone
from api.models.campaignModel import PromotionCampaign
from api.models.freeSubscriptionTrialModel import FreeTrial
from simple_history.models import HistoricalRecords
from .userModel import User
from .postsModel import *
from .userSubscriptionTierModel import *


class SubscriptionHistory(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='user_subscription_history', on_delete=models.DO_NOTHING, null=True, blank=True)
    details = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='subscription_history_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'subscription_history'
        indexes = [
            models.Index(fields=['id'])
        ]
