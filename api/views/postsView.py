from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from api.services.posts import PostsService

postService = PostsService()

role_schema = AutoSchema(manual_fields=[
    coreapi.Field(
        "name",
        required=True,
        location="form",
        schema=coreschema.String()
    )
])


class ListCreateUpdateDeletePostView(APIView):
    def get(self, request, format=None):
        """
        Retun all the Posts.
        """
        result = postService.get_post_list(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create New Posts. 
        """
        result = postService.create_post(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        """
        Updates Post
        """
        result = postService.update_post(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk,  format=None):
        """
        Delete Posts. 
        """
        result = postService.delete_post(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetPostCountsByUserIDView(APIView):
    permission_classes = (AllowAny,)
    def get(self, request,user_name, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.get_post_count_by_user_id(request, user_name, format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetTotalPostCountsView(APIView):
    permission_classes = (AllowAny,)
    def get(self, request, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.get_total_post_count(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetPostPaginationView(APIView):
    def post(self, request, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.get_post_list_with_pagination(request, format=None)
        return Response(result, status=status.HTTP_200_OK)  

class GetLoungePostPaginationView(APIView):
    def post(self, request, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.get_lounge_post_list_with_pagination(request, format=None)
        return Response(result, status=status.HTTP_200_OK)  

class GetPostView(APIView):
    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.get_post(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class PostByUserIDView(APIView):
    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.get_posts_by_user_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class PostPaginationByUserIDView(APIView):
    permission_classes = (AllowAny,)
    def post(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.get_pagination_posts_by_user_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class LikePostView(APIView):
    def post(self, request, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.like_post(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UnLikePostView(APIView):
    def post(self, request, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.unlike_post(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

   

class CommentPostView(APIView):
    def post(self, request, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.comment_post(request, format=None)
        return Response(result, status=status.HTTP_200_OK)


class PostPaginationByPageIDView(APIView):
    def get(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = postService.get_posts_by_page_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)



class PostPayment(APIView):
    def post(self, request, format=None):
        result = postService.send_payment_for_post(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def get(self, request, format=None):
        result = postService.unlock_post(request, format=None)
        return Response(result, status=status.HTTP_200_OK)