from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from api.services.post_comment_likes.post_comment_like_service import PostCommentLikeService

service = PostCommentLikeService()


class PostCommentLikeView(APIView):
    def post(self, request):
        result = service.toggle_comment_like(request)
        return Response(result)
