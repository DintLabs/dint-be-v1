from operator import mod
from statistics import mode
from django.db import models
from django.utils import timezone
from api.models.postsModel import Posts
from simple_history.models import HistoricalRecords
from .userModel import User


class PostComments(models.Model):
    id = models.AutoField(primary_key=True)
    post = models.ForeignKey(Posts, related_name='post_comment', on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey(User, related_name='user_comment', on_delete=models.CASCADE, null=True, blank=True)
    comment = models.TextField(null=True, blank=True)

    room_type = models.CharField(max_length=50, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='post_comments_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'post_comments'
        indexes = [
            models.Index(fields=['id'])
        ]
