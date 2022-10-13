from operator import mod
from statistics import mode
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords
from .userModel import User
from .pageModel import Page


class Posts(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='user_posts', on_delete=models.DO_NOTHING, null=True, blank=True)
    page = models.ForeignKey(Page, related_name='post_page', on_delete=models.DO_NOTHING, null=True, blank=True)
    type = models.CharField(max_length=50, null=True, blank=True)
    content = models.TextField(null=True, blank=True)
    media = models.URLField(max_length = 500, null=True, blank=True)
    total_likes = models.IntegerField(null=True, blank=True)
    total_comments = models.IntegerField(null=True, blank=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='posts_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'posts'
        indexes = [
            models.Index(fields=['id'])
        ]
