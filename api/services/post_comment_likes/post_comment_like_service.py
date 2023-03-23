from rest_framework.exceptions import ValidationError
from rest_framework.request import Request

from api.models import PostCommentLike


class PostCommentLikeService:
    def toggle_comment_like(self, request: Request) -> dict:
        comment_id = request.data.get('comment')

        if not comment_id:
            raise ValidationError({'error': 'Comment ID is required'})

        like, created = PostCommentLike.objects.get_or_create(user=request.user, comment_id=comment_id)

        if not created:
            like.delete()

        return {'liked': created}
