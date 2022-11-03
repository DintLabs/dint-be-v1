from operator import mod
from statistics import mode
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords
from .userModel import User
from .postsModel import *


class UserFeeds(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='user_feeds', on_delete=models.CASCADE, null=True, blank=True)
    post = models.ForeignKey(Posts, related_name='user_posts', on_delete=models.CASCADE, null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='user_feeds_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'user_feeds'
        indexes = [
            models.Index(fields=['id'])
        ]
