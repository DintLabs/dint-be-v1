from ast import excepthandler
import re
from urllib import response
from api.models.UserSubscriptionModel import UserSubscription
from api.models.userModel import User
from api.models.userSubscriptionTierModel import UserSubscriptionTier
from api.serializers.connections import *
from api.utils import CustomPagination
from rest_framework import status
from api.utils.messages.commonMessages import *
from api.utils.messages.eventMessages import *

from .connectionBaseService import ConnectionBaseService


class ConnectionService(ConnectionBaseService):
    """
    Create, Retrieve, Update or Delete a Tier instance and Return all Tier.
    """

    def __init__(self):
        pass

    def follow(self, request, pk, format=None):
        """
        Retun all the Tiers by User ID.
        """

        try:
            obj = UserFollowers.objects.get(user = pk, follower = request.user.id)
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "You Already Follow this user."})
        except UserFollowers.DoesNotExist:
            pass

        try:
            follow_user_obj = User.objects.get(id = pk)
        except User.DoesNotExist:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        request.data['user'] = pk
        request.data['follower'] = request.user.id

        if follow_user_obj.is_private is True:
            request.data['request_status'] = None
            message = "Follow Request Sent Successfully."
        else:
            request.data['request_status'] = True
            message = "Followed Successfully."
        
        serializer = CreateUpdateConnectionSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": message})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
        

    def unfollow(self, request, pk, format=None):
        """
        Return all the Tiers by User ID.
        """
        try:
            obj = UserFollowers.objects.get(user = pk, follower = request.user.id)
        except UserFollowers.DoesNotExist:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        obj.delete()
        return ({"data": None, "code": status.HTTP_200_OK, "message": "Unfollowed Successfully."})

    def remove_follower_by_user_id(self, request, pk, format=None):
        """
        Return all the Tiers by User ID.
        """
        try:
            obj = UserFollowers.objects.get(user = request.user.id, follower = pk)
        except UserFollowers.DoesNotExist:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        obj.delete()
        return ({"data": None, "code": status.HTTP_200_OK, "message": "Follower Removed Successfully."})

    
    def get_follow_request_list(self, request,format=None):
        """
        Get Follow Request List
        """

        req_obj = UserFollowers.objects.filter(user = request.user.id, request_status = None)
        serializer = GetConnectionSerializer(req_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Requests Fetched Successfully."})


    def update_follow_request_status(self, request, pk, format=None):
        """
        Return all the Tiers by User ID.
        """
        try:
            obj = UserFollowers.objects.get(id = pk)
        except UserFollowers.DoesNotExist:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        if obj.request_status is None:
            obj.request_status = request.data['request_status']
            obj.save()
            return ({"data": None, "code": status.HTTP_200_OK, "message": "Status of this request changed to {}".format(str(obj.request_status))})
        else:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Status of this request is already Set to " + str(obj.request_status)})
      
    def get_follower_list(self, request, format=None):
        """
        Retun all the Tiers by User ID.
        """
        sub_obj = UserFollowers.objects.filter(user = request.user.id, request_status = True).values_list('follower')
        follower_obj = User.objects.filter(id__in = sub_obj)
        serializer = UserLoginDetailSerializer(follower_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Follower List Fecthed."})

    def get_following_list(self, request, format=None):
        """
        Retun all the Tiers by User ID.
        """
        sub_obj = UserFollowers.objects.filter(follower = request.user.id, request_status = True).values_list('user')
        follower_obj = User.objects.filter(id__in = sub_obj)
        serializer = UserLoginDetailSerializer(follower_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Following List Fecthed."})


    def delete_follow_request(self, request, pk, format=None):
        """
        Cancel Follow Request
        """
        try:
            obj = UserFollowers.objects.get(user = pk, follower = request.user.id)
        except UserFollowers.DoesNotExist:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        obj.delete()
        return ({"data": None, "code": status.HTTP_200_OK, "message": "Follow Request Canceled Successfully."})

    def update_privacy_status(self, request, format=None):
        """
        Update Privacy Settings
        """

        user_obj = User.objects.get(id = request.user.id)
        if user_obj.is_private is True:
            user_obj.is_private = False
            message = 'Account switched to Public'
        else:
            user_obj.is_private = True
            message = 'Account switched to Private'
        user_obj.save()
        return ({"data": None, "code": status.HTTP_200_OK, "message": message})


    


    