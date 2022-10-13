from operator import mod
from statistics import mode
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords
from .userModel import User


class ChatRoom(models.Model):
    id = models.AutoField(primary_key=True)
    reciever = models.ForeignKey(User, related_name='chat_room_reciever', on_delete=models.DO_NOTHING, null=True, blank=True)
    sender = models.ForeignKey(User, related_name='chat_room_sender', on_delete=models.DO_NOTHING, null=True, blank=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='chat_room_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'chat_room'
        indexes = [
            models.Index(fields=['id'])
        ]
