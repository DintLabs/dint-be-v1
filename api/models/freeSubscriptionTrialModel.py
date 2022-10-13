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


class FreeTrial(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='trial_user', on_delete=models.DO_NOTHING, null=True, blank=True)
    page = models.ForeignKey(Page, related_name='trial_page', on_delete=models.DO_NOTHING, null=True, blank=True)
    offer_limit = models.IntegerField(default = 1, null=True, blank=True)
    offer_expiration = models.IntegerField(default = 1, null=True, blank=True)
    trial_duration = models.IntegerField(default = 1, null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='free_trial_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'free_trial'
        indexes = [
            models.Index(fields=['id'])
        ]
