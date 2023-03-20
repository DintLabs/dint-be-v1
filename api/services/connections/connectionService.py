from ast import excepthandler
import re
from urllib import response
from api.models.UserSubscriptionModel import UserSubscription
from api.models.messageNotificationModel import Notifications
from api.models.userModel import User
from api.models.userSubscriptionTierModel import UserSubscriptionTier
from api.serializers.connections import *
from api.utils import CustomPagination
from rest_framework import status
from api.utils.messages.commonMessages import *
from api.utils.messages.eventMessages import *
from rest_framework.parsers import MultiPartParser, FormParser
from .connectionBaseService import ConnectionBaseService
import datetime
from django.utils import timezone
from django.dispatch import receiver
from django.db.models.signals import post_save

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

            follow_requests = UserFollowers.objects.filter(user = request.user.id, request_status = None).update(request_status = True) 
            print(follow_requests)
            message = 'Account switched to Public'
        else:
            user_obj.is_private = True
            message = 'Account switched to Private'
        user_obj.save()
        return ({"data": None, "code": status.HTTP_200_OK, "message": message})

    def get_stories(self, request, format=None):

        sub_obj = UserFollowers.objects.filter(follower = request.user.id, request_status = True).values_list('user')
        follower_obj = User.objects.filter(id__in = sub_obj)
        context = {"logged_in_user":request.user.id}
        serializer = GetUserStoriesModelSerializer(follower_obj, many=True, context=context)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Stories List Fecthed."})

    
    def create_stories(self, request, format=None):
        parser_classes = (MultiPartParser, FormParser)
        user_obj = User.objects.get(id = request.user.id)
      
        #user_story = UserStories.objects.create(user = user_obj, story = request.FILES['story'])
        serializer = UserStoriesModelSerializer(data = request.data)

        if serializer.is_valid():
            serializer.save()
            res = serializer.data
            storyURL = request.build_absolute_uri(res["story"])
            res["story"] = storyURL
            return ({"data": res, "code": status.HTTP_200_OK, "message": "Story posted successfully."})
        else:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Something went wrong."}) 

    def delete_stories(self, request, pk, format=None):
        try:
            user_story = UserStories.objects.get(user = request.user, id=pk)
            user_story.delete()
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Story deleted successfully"})
        except:
             return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

    def get_stories_by_user(self, request, format=None):
        try:
            expire_time = timezone.now() - datetime.timedelta(hours=24)
            user_all_stories = UserStories.objects.filter(user = request.user, created_at__gt = expire_time)
            serializer = UserStoriesModelSerializer(user_all_stories, many=True)
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User Stories List Fecthed."})
        except:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

    def get_connections_count(self, request, pk, format=None):
        print(pk)
        user_obj = User.objects.get(id = pk)
        followers_count = sub_obj = UserFollowers.objects.filter(user = user_obj, request_status = True).count()

        following_count = UserFollowers.objects.filter(follower = user_obj, request_status = True).count()

        data = {
            "total-followers":followers_count,
            "total-following":following_count
        }

        return ({"total-followers": followers_count, "total-following" : following_count, "code": status.HTTP_200_OK, "message": "User Stories List Fecthed."})


@receiver(post_save, sender=UserFollowers)
def subscribe_saved(sender,instance,created,**kwargs):
    if created:
        #print("New Request Created", instance.id)
        NotificationInstance = Notifications(followrequest=instance, type_of_notification='New Follow Request')
        NotificationInstance.save()
        #print(NotificationInstance.id)

   