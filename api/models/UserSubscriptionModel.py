from operator import mod
from pyexpat import model
from statistics import mode
from django.db import models
from django.utils import timezone
from api.models.campaignModel import PromotionCampaign
from api.models.freeSubscriptionTrialModel import FreeTrial
from simple_history.models import HistoricalRecords
from .userModel import User
from .postsModel import *
from .userSubscriptionTierModel import *


class UserSubscription(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='user_subscription', on_delete=models.DO_NOTHING, null=True, blank=True)
    page = models.ForeignKey(Page, related_name='page_subscription', on_delete=models.DO_NOTHING, null=True, blank=True)
    subscription_tier = models.ForeignKey(UserSubscriptionTier, related_name='user_subscription_tier', on_delete=models.DO_NOTHING, null=True, blank=True)
    promotion_campaign = models.ForeignKey(PromotionCampaign, related_name='subscription_promotion_campaign', on_delete=models.DO_NOTHING, null=True, blank=True)
    free_trial = models.ForeignKey(FreeTrial, related_name='subscription_free_trial', on_delete=models.DO_NOTHING, null=True, blank=True)

    subscription_type = models.IntegerField(null=True, blank=True, help_text='1. Basic, 2. Bundle, 3. Promotion, 4. Trial')
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    reject_reason = models.CharField(max_length=100, null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='user_subscription_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'user_subscription'
        indexes = [
            models.Index(fields=['id'])
        ]


class UserTipReference(models.Model):
    to_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='to_user' )
    from_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='from_user')
    reference = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)