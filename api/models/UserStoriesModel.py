from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords
from .userModel import User

class UserStories(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_stories')
    story = models.FileField(upload_to='stories/')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_highlighted = models.BooleanField(default=False)
    is_archived = models.BooleanField(default=False)
    expiration_time = models.DateTimeField(blank=True, null=True)
    class Meta:
        db_table = 'user_stories'
        indexes = [
            models.Index(fields=['id'])
        ]

class UserStoriesLikes(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    story = models.ForeignKey(UserStories, related_name='liked_story', on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    
    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'story_likes'
        indexes = [
            models.Index(fields=['id'])
        ]