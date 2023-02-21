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
from .messagesModel import *







class Notifications(models.Model):
    id = models.AutoField(primary_key=True)
    # message = models.ForeignKey(Messages, related_name='notification_message', on_delete=models.DO_NOTHING, null=True, blank=True)
    message = models.ForeignKey(Messages, on_delete=models.CASCADE, related_name='notification_message' )
    type_of_notification=models.CharField(max_length=264,null=True,blank=True)
    

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    # history = HistoricalRecords(table_name='notification_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'notifications'
        indexes = [
            models.Index(fields=['id'])
        ]
