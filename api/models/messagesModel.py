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


class Messages(models.Model):
    id = models.AutoField(primary_key=True)
    reciever = models.ForeignKey(User, related_name='reciever_user', on_delete=models.DO_NOTHING, null=True, blank=True)
    sender = models.ForeignKey(User, related_name='sender_user', on_delete=models.DO_NOTHING, null=True, blank=True)
    chat_room = models.ForeignKey(ChatRoom,related_name='message_chat_room', on_delete=models.DO_NOTHING, null=True, blank=True)
    content = models.TextField(null=True,blank=True)
    is_seen = models.BooleanField(default=False)
    is_edited = models.BooleanField(default=False)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='messages_history')
    can_delete = models.BooleanField(default=True)


    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'messages'
        indexes = [
            models.Index(fields=['id'])
        ]
