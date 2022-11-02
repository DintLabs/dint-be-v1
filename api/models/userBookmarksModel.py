from django.db import models
from .userModel import User
from .postsModel import Posts

class UserBookmarks(models.Model):
    user = models.ForeignKey(User, related_name='bookmarks', on_delete=models.CASCADE, null=True, blank=True)
    post = models.ForeignKey(Posts, related_name='bookmark_post', on_delete=models.CASCADE, null=True, blank=True)
    
    class Meta:
        db_table = 'user_bookmarks'
        indexes = [
            models.Index(fields=['id'])
        ]


       