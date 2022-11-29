from operator import mod
from statistics import mode
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords
from .userModel import User
from .postsModel import *
from .userFeedsModel import *
from .UploadMediaModel import *


class UserFollowers(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='user_follower', on_delete=models.DO_NOTHING, null=True, blank=True)
    follower = models.ForeignKey(User, related_name='user_following', on_delete=models.DO_NOTHING, null=True, blank=True)
    request_status = models.BooleanField(default=None, null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='user_follower_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'user_follower'
        indexes = [
            models.Index(fields=['id'])
        ]


class UserStories(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_stories')
    story = models.FileField(upload_to='stories/')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

