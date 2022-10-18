from django.db import models
from .userModel import User

class UserBookmarks(models.Model):
    user = models.ForeignKey(User, related_name='user_bookmark', on_delete=models.DO_NOTHING, null=True, blank=True)
    bookmark_type = models.IntegerField()
    title = models.CharField(max_length=255)

    class Meta:
        db_table = 'user_bookmarks'
        indexes = [
            models.Index(fields=['id'])
        ]