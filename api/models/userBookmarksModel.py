from django.db import models
from .userModel import User
from .postsModel import Posts
from django.utils import timezone

class UserBookmarks(models.Model):
    user = models.ForeignKey(User, related_name='bookmarks', on_delete=models.CASCADE, null=True, blank=True)
    post = models.ForeignKey(Posts, related_name='bookmark_post', on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'user_bookmarks'
        indexes = [
            models.Index(fields=['id'])
        ]


       