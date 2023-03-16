from email.policy import default
from operator import mod
from re import T
from statistics import mode
from django.db import models
from django.utils import timezone
from api.models.chatRoomModel import ChatRoom
from simple_history.models import HistoricalRecords
from .userModel import User
from .postsModel import *
from .userFeedsModel import *
from .UploadMediaModel import *


class PromotionCampaign(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='campaign_user', on_delete=models.DO_NOTHING, null=True, blank=True)
    page = models.ForeignKey(Page, related_name='campaign_page', on_delete=models.DO_NOTHING, null=True, blank=True)
    campaign_type = models.IntegerField(default = 1, help_text="1. New User, 2. Expired Subscriber User 3. Both")
    offer_limit = models.IntegerField(default = 5)
    offer_expiration_in_days = models.IntegerField(default=5)
    discount_percentage = models.FloatField(null=True, blank=True)
    message = models.CharField(max_length=500, null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='promotion_campaign_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'promotion_campaign'
        indexes = [
            models.Index(fields=['id'])
        ]
