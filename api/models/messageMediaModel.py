
from django.db import models
from django.utils import timezone
from api.models.messagesModel import Messages
from simple_history.models import HistoricalRecords


class MessageMedia(models.Model):
    id = models.AutoField(primary_key=True)
    message = models.ForeignKey(Messages, related_name='reciever_user', on_delete=models.DO_NOTHING, null=True, blank=True)
    media = models.URLField(max_length=1000)
  
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='message_media_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'message_media'
        indexes = [
            models.Index(fields=['id'])
        ]
