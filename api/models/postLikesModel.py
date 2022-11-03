from operator import mod
from statistics import mode
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords
from .userModel import User
from .postsModel import *
from .userFeedsModel import *
from .UploadMediaModel import *


class PostLikes(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='like_user', on_delete=models.CASCADE, null=True, blank=True)
    post = models.ForeignKey(Posts, related_name='like_post', on_delete=models.CASCADE, null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='post_likes_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'post_likes'
        indexes = [
            models.Index(fields=['id'])
        ]
