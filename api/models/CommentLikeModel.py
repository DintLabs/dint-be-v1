from django.conf import settings
from django.db import models
from django.utils import timezone


class PostCommentLike(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='liked_comments',
        null=True,
        on_delete=models.SET_NULL
    )
    comment = models.ForeignKey(
        'PostComments',
        related_name='likes',
        on_delete=models.CASCADE
    )
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'Like for {self.user}'
