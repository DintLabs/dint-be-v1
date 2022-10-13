from api.models import Role
from api.models.postLikesModel import PostLikes
from api.models.userFollowersModel import UserFollowers
# from api.models.PageModel import Posts
from api.serializers.posts import *
from api.utils import CustomPagination
from rest_framework import status
from api.utils.messages.commonMessages import *
from api.utils.messages.postMessages import *
from api.serializers.page import *
import string
import random

from .pageBaseService import PageBaseService


class PageService (PageBaseService):
    """
    Create, Retrieve, Update or Delete a Posts instance and Return all Posts.
    """

    def __init__(self):
        pass

    def get_page_list(self, request, format=None):
        """
        Retun all the Posts.
        """
        page_obj = Page.objects.all()
        serializer = GetPageSerializer (page_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def get_page_list_with_pagination(self, request, format=None):
        """
        Return all the Posts with Pagination.
        """
        page_obj = Page.objects.all()
        custom_pagination = CustomPagination ()
        search_keys = ['title__icontains', 'id__contains']
        search_type = 'or'
        roles_response = custom_pagination.custom_pagination(request, Page, search_keys, search_type, GetPageSerializer, page_obj)
        return {"data": roles_response['response_object'],
                "recordsTotal": roles_response['total_records'],
                "recordsFiltered": roles_response['total_records'],
                "code": status.HTTP_200_OK, "message": OK}


    def create_page(self, request, format=None):
        """
        Create New Posts. 
        """
        try:
            page_obj = Page.objects.get(user = request.data['user'], type = request.data['type'])
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Page for this User is already created!"})
        except Page.DoesNotExist:
            pass
        page_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        request.data['page_name'] = page_name
        serializer = CreateUpdatePageSerializer(data=request.data)
        if serializer.is_valid ():
            serializer.save ()
            return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": POST_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def delete_page(self, request, pk, format=None):
        """
        Delete Posts. 
        """
        try:
            page_obj = Page.objects.get(id = pk)
        except Page.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        
        page_obj.delete ()
        return ({"code": status.HTTP_200_OK, "message": POST_DELETED})



    def update_page(self, request, pk, format=None):
        """
        Updates Post
        """
        data = request.data
        try:
            page_obj = Page.objects.get(id = pk)
        except Page.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = CreateUpdatePageSerializer(page_obj, data=data)
        if serializer.is_valid ():
            serializer.save ()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_UPDATED})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
     
    def get_page(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            page_obj = Page.objects.get(id = pk)
        except Page.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        context = {"user_id":request.user.id}
        serializer = GetPageSerializer(page_obj, context = context)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})


    def get_pages_by_user_id(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            page_obj = Page.objects.filter(user = pk)
        except Page.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = GetPageSerializer(page_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def get_pagination_pages_by_user_id(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        page_obj = Page.objects.filter(user = pk)
            
        custom_pagination = CustomPagination ()
        search_keys = ['title__icontains', 'id__contains']
        search_type = 'or'
        roles_response = custom_pagination.custom_pagination(request, Page, search_keys, search_type, GetPageSerializer, page_obj)
        return {"data": roles_response['response_object'],
                "recordsTotal": roles_response['total_records'],
                "recordsFiltered": roles_response['total_records'],
                "code": status.HTTP_200_OK, "message": OK}

    
    def search_page(self, request, format=None):

        follower_list = list(UserFollowers.objects.filter(follower = request.user.id).values_list('user', flat=True))
        public_user = list(User.objects.filter(is_private = False).values_list('id', flat=True))
        follower_list.extend(public_user)
        page_obj = Page.objects.filter(title__icontains = request.data[''])
            
        custom_pagination = CustomPagination ()
        search_keys = ['title__icontains', 'id__contains']
        search_type = 'or'
        roles_response = custom_pagination.custom_pagination(request, Page, search_keys, search_type, GetPageSerializer, page_obj)
        return {"data": roles_response['response_object'],
                "recordsTotal": roles_response['total_records'],
                "recordsFiltered": roles_response['total_records'],
                "code": status.HTTP_200_OK, "message": OK}

    def page_by_page_name(self, request, page_name, format=None):
        try:
            page_obj = Page.objects.get(page_name = page_name)
        except Page.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        context = {"user_id":request.user.id}
        serializer = GetPageSerializer(page_obj, context = context)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def check_username_availability(self, request, user_name, format=None):
        try:
            page_obj = Page.objects.get(page_name = user_name)
            return ({"data": {"page_id":page_obj.id}, "code": status.HTTP_200_OK, "message": "Page Already Exists with User Name"})
        except:
            try:
                user_obj = User.objects.get(custom_username = user_name)
                return ({"data": {"user_id":user_obj.id}, "code": status.HTTP_200_OK, "message": "User Already Exists with User Name"})
            except:
                return ({"data":None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})