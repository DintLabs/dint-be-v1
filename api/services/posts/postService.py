from api.models import Role
from api.models.postLikesModel import PostLikes
from api.models.postsModel import Posts
from api.models.userFollowersModel import UserFollowers
from api.serializers.posts import *
from api.utils import CustomPagination
from rest_framework import status
from api.utils.messages.commonMessages import *
from api.utils.messages.postMessages import *

from .postBaseService import PostsBaseService


class PostsService (PostsBaseService):
    """
    Create, Retrieve, Update or Delete a Posts instance and Return all Posts.
    """

    def __init__(self):
        pass

    def get_post_list(self, request, format=None):
        """
        Retun all the Posts.
        """
        post_obj = Posts.objects.all()
        context = {"logged_in_user":request.user.id}
        serializer = GetPostsSerializer(post_obj, context = context, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def get_post_list_with_pagination(self, request, format=None ):
        """
        Return all the Posts with Pagination.
        """

        post_type = request.data.get('post_type')
        if post_type is None or post_type == 'all':
            post_obj = Posts.objects.all()
        else:
            post_obj = Posts.objects.filter(type = post_type)

        custom_pagination = CustomPagination()
        search_keys = ['content__icontains', 'id__contains']
        search_type = 'or'
        context = {"logged_in_user":request.user.id}
        roles_response = custom_pagination.custom_pagination(request, Posts, search_keys, search_type, GetPostsSerializer, post_obj, context )
        return {"data": roles_response['response_object'],
                "recordsTotal": roles_response['total_records'],
                "recordsFiltered": roles_response['total_records'],
                "code": status.HTTP_200_OK, "message": OK}

    

    def get_lounge_post_list_with_pagination(self, request, format=None):
        """
        Return all the Posts with Pagination.
        """

        post_type = request.data.get('post_type')
        if post_type is None or post_type == 'all':
            post_obj = Posts.objects.filter(page__isnull = True).all()
        else:
            post_obj = Posts.objects.filter(type = post_type, page__isnull = True)

        follower_list = UserFollowers.objects.filter(follower = request.user.id).values_list('user')
        follower_post_obj = post_obj.filter(user__in = follower_list)
        own_post_obj = post_obj.filter(user = request.user.id)
        final_obj = follower_post_obj | own_post_obj

        custom_pagination = CustomPagination()
        search_keys = ['content__icontains', 'id__contains']
        search_type = 'or'
        context = {"logged_in_user":request.user.id}
        roles_response = custom_pagination.custom_pagination(request, Posts, search_keys, search_type, GetPostsSerializer, final_obj, context)
        return {"data": roles_response['response_object'],
                "recordsTotal": roles_response['total_records'],
                "recordsFiltered": roles_response['total_records'],
                "code": status.HTTP_200_OK, "message": OK}



    def create_post(self, request, format=None):
        """
        Create New Posts. 
        """
        serializer = CreateUpdatePostsSerializer(data=request.data)
        if serializer.is_valid ():
            serializer.save ()
            res_data = GetPostsSerializer(Posts.objects.get(id = serializer.data['id'])).data
            return ({"data": res_data, "code": status.HTTP_201_CREATED, "message": POST_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def delete_post(self, request, pk, format=None):
        """
        Delete Posts. 
        """
        try:
            post_obj = Posts.objects.get(id = pk)
        except Posts.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        
        post_obj.delete ()
        return ({"code": status.HTTP_200_OK, "message": POST_DELETED})


    def get_post_count_by_user_id(self, request, user_name, format=None):
        user_obj = Posts.objects.filter(user = user_name)
        data = {
            "all_posts":user_obj.count(),
            "text_posts":user_obj.filter(type = 'text').count(),
            "image_posts":user_obj.filter(type = 'image').count(),
            "video_posts":user_obj.filter(type = 'video').count()
        }
        return ({"data": data, "code": status.HTTP_200_OK, "message": POST_DELETED})

    

    def get_total_post_count(self, request, format=None):
        follower_list = UserFollowers.objects.filter(follower = request.user.id).values_list('user')
        follower_post_obj = Posts.objects.filter(user__in = follower_list)
        
        
        try:
            own_post_obj = Posts.objects.filter(user = request.user.id)
            final_obj = follower_post_obj | own_post_obj
        except:
            print('---------------------------------_<><><><>')
            final_obj = follower_post_obj

        data = {
            "all_posts":final_obj.count(),
            "text_posts":final_obj.filter(type = 'text').count(),
            "image_posts":final_obj.filter(type = 'image').count(),
            "video_posts":final_obj.filter(type = 'video').count()
        }
        return ({"data": data, "code": status.HTTP_200_OK, "message": POST_DELETED})


    def update_post(self, request, pk, format=None):
        """
        Updates Post
        """
        data = request.data
        try:
            post_obj = Posts.objects.get(id = pk)
        except Posts.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = CreateUpdatePostsSerializer(post_obj, data=data)
        if serializer.is_valid ():
            serializer.save ()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_UPDATED})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
     
    def get_post(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            post_obj = Posts.objects.get(id = pk)
        except Posts.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = GetPostsSerializer(post_obj)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    

    def get_posts_by_user_id(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            post_obj = Posts.objects.filter(user = pk)
        except Posts.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        context = {"logged_in_user":request.user.id}
        serializer = GetPostsSerializer(post_obj, context = context, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def get_pagination_posts_by_user_id(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        if 'page' in request.data and request.data['page'] is not None:
            post_obj = Posts.objects.filter(page = request.data['page'])
        else:
            try:
                user_obj = User.objects.get(id = pk)
            except:
                return ({"data":None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
            
            if user_obj.is_private is True and user_obj.id != request.user.id:
                try:
                    follow_flag = UserFollowers.objects.get(user = pk, follower = request.user.id)

                except UserFollowers.DoesNotExist:
                    return ({"data":None, "code": status.HTTP_400_BAD_REQUEST, "message": "Please follow this user to view Posts."})
        
            post_obj = Posts.objects.filter(user = pk , page__isnull = True)

        post_type = request.data.get('post_type')
        if post_type is not None and post_type != 'all':
            post_obj = post_obj.filter(type = post_type)
            
        custom_pagination = CustomPagination ()
        search_keys = ['content__icontains', 'id__contains']
        search_type = 'or'
        context = {"logged_in_user":request.user.id}
        roles_response = custom_pagination.custom_pagination(request, Posts, search_keys, search_type, GetPostsSerializer, post_obj , context)
        return {"data": roles_response['response_object'],
                "recordsTotal": roles_response['total_records'],
                "recordsFiltered": roles_response['total_records'],
                "code": status.HTTP_200_OK, "message": OK}


    def like_post(self, request, format=None):
        """
        Create New Posts. 
        """
        serializer = CreateUpdatePostLikeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": POST_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})


    def unlike_post(self, request, format=None):
        """
        unlike  Posts. 
        """
        post_obj = request.data['post']
        user_obj = request.data['user']
        try:
            liked_post = PostLikes.objects.get(post = post_obj, user = user_obj)
        except :
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})            

        liked_post.delete()
        return ({"data": [], "code": status.HTTP_201_CREATED, "message": "post unliked successfully"})


    def comment_post(self, request, format=None):
        """
        Create New Posts. 
        """
        serializer = CreateUpdatePostsCommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": POST_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
       

    def get_posts_by_page_id(self, request, pk, format=None):
        """
        Return all the Posts with Pagination.
        """

        post_type = request.data.get('post_type')
        if post_type is None or post_type == 'all':
            post_obj = Posts.objects.filter(page = pk).all()
        else:
            post_obj = Posts.objects.filter(type = post_type, page = pk)

        # subscriber_list = UserSubscription.objects.filter(user_subscription = request.user.id).values_list('user')
        # subscriber_post_obj = post_obj.filter(user__in = subscriber_list)
        # own_post_obj = post_obj.filter(user = request.user.id)
        # final_obj = follower_post_obj | own_post_obj

        custom_pagination = CustomPagination()
        search_keys = ['content__icontains', 'id__contains']
        search_type = 'or'
        context = {"logged_in_user":request.user.id}
        roles_response = custom_pagination.custom_pagination(request, Posts, search_keys, search_type, GetPostsSerializer, post_obj, context)
        return {"data": roles_response['response_object'],
                "recordsTotal": roles_response['total_records'],
                "recordsFiltered": roles_response['total_records'],
                "code": status.HTTP_200_OK, "message": OK}