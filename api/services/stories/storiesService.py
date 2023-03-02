from ast import excepthandler
import re
from urllib import response
from api.serializers.stories import UserStoryLikesSerializer
from api.serializers.stories import *
from api.models.userFollowersModel import *
from rest_framework import status
from api.utils.messages.commonMessages import *
from api.utils.messages.eventMessages import *
from rest_framework.parsers import MultiPartParser, FormParser
from .storiesBaseService import StoriesBaseService
from django.utils import timezone
from django.forms.models import model_to_dict
import datetime
from api.models.UserStoriesModel import UserStoriesLikes, UserStories
import pytz

class StoriesService(StoriesBaseService):
    """
    Create, Retrieve, Update or Delete a Tier instance and Return all Tier.
    """

    def __init__(self):
        pass

    def get_stories(self, request, format=None):
        sub_obj = UserFollowers.objects.filter(follower = request.user.id, request_status = True).values_list('user')
        expire_time = timezone.now() - datetime.timedelta(hours=24)
        userstories = UserStories.objects.filter(user__in=sub_obj, created_at__gt = expire_time).values_list('user')
        follower_obj = User.objects.filter(id__in = userstories)
        context = {"logged_in_user":request.user.id}
        serializer = GetUserStoriesModelSerializer(follower_obj, many=True, context=context)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Stories List Fecthed."})

    def create_stories(self, request, format=None):
        parser_classes = (MultiPartParser, FormParser)
        user_obj = User.objects.get(id = request.user.id)
      
        serializer = CreateUserStoriesSerrializer(data = request.data)
       
        if serializer.is_valid():
            serializer.save()
            res = serializer.data
            storyURL = request.build_absolute_uri(res["story"])
            tz = pytz.timezone('Asia/Kolkata')
            expire_time = datetime.datetime.now(tz) + datetime.timedelta(hours=24)
            res["story"] = storyURL
            res["expiration_time"] = expire_time
            user_obj = UserStories.objects.filter(id = res["id"]).update(expiration_time = expire_time)
            return ({"data": res, "code": status.HTTP_200_OK, "message": "Story posted successfully."})
        else:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Something went wrong."}) 

    def delete_stories(self, request, pk, format=None):
        try:
            user_story = UserStories.objects.get(user = request.user, id = pk)
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
  
    def like_stories(self, request, pk, format=None):
        already_liked = UserStoriesLikes.objects.filter(user = request.user.id, story = pk)
       
        if already_liked:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message":"story already liked"})
        else:
            story = UserStories.objects.filter(id = pk)
            if story:
                story_obj = UserStories.objects.get(id = pk)
                like_story = UserStoriesLikes.objects.create(user = request.user, story = story_obj)
                data = model_to_dict(like_story)
                serializer = UserStoryLikesSerializer(data = data)
                if serializer.is_valid():
                    serializer.save()
                    return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Story liked successfully"})
            else:
                return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Story not found"})
      
    def unlike_stories(self, request, pk, format=None):
        try:
            liked_story = UserStoriesLikes.objects.get(story = pk, user = request.user.id)
        except Exception as e:
            print(e)
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})            
        liked_story.delete()
        return ({"data": [], "code": status.HTTP_201_CREATED, "message": "post unliked successfully"})
    
    def create_story_archive(self, request, format=None):
        user_obj = request.user
        story = request.data['story']
        story_obj = UserStories.objects.filter(user = user_obj, id = story)
        if story_obj:
            already_archived = UserStories.objects.filter(user = user_obj, id = story, is_archived = True)
            if not already_archived:
                create_archive = UserStories.objects.filter(user = user_obj, id = story).update(is_archived = True)
                serializer = CreateUserStoriesSerrializer(data = request.data)
                get_archive = UserStories.objects.filter(user = user_obj, id = story)
                serializer = UserStoriesModelSerializer(get_archive, many=True)
                return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Story archived successfully"})
            else:
                return ({"data": [], "code": status.HTTP_200_OK, "message": "Story already archived"})
        else:
            return ({"data": [], "code": status.HTTP_200_OK, "message": "Data not found"})
        return ({"data": [], "code": status.HTTP_200_OK, "message": "Something went wrong"})

    def get_story_archive(self, request,format=None):
        user_obj = request.user
        UserStories_obj = UserStories.objects.filter(user = user_obj, is_archived = True)
        if UserStories_obj:
            serializer = UserStoriesModelSerializer(UserStories_obj, many=True)
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Archived stories fetched"})
        else:
            UserStories_obj = None
            return ({"data": UserStories_obj, "code": status.HTTP_200_OK, "message": "Archived stories fetched"})
        return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Something went wrong"})

    def delete_story_archive(self, request, pk, format=None):
        user_obj = request.user
        story_obj = UserStories.objects.filter(user = user_obj, id = pk, is_archived = True)
        if story_obj:
            story_obj.delete()
            return ({"data": [], "code": status.HTTP_200_OK, "message": "Story removed from archived"})
        else:
            return ({"data": [], "code": status.HTTP_200_OK, "message": "Data not found"})
        return ({"data": [], "code": status.HTTP_200_OK, "message": "Something went wrong"})

    def create_story_highlight(self, request, format=None):
        user_obj = request.user
        story = request.data['story']
        story_obj = UserStories.objects.filter(user = user_obj, id = story)
        if story_obj:
            already_highlighted = UserStories.objects.filter(user = user_obj, id = story, is_highlighted = True)
            if not already_highlighted:
                create_highlight = UserStories.objects.filter(user = user_obj, id = story).update(is_highlighted = True)
                return ({"data": [], "code": status.HTTP_200_OK, "message": "Story added to highlights successfully"})
            else:
                return ({"data": [], "code": status.HTTP_200_OK, "message": "Story already highlighted"})
        else:
            return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "No data found"})
    
    def get_story_highlights(self, request, format=None):
        user_obj = request.user
        stories_obj = UserStories.objects.filter(user = user_obj,is_highlighted = True)
        if stories_obj:
            serializer = UserStoriesModelSerializer(stories_obj, many=True)
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User Stories List Fecthed."})
        else:
            stories_obj = None
            return ({"data": stories_obj, "code": status.HTTP_200_OK, "message": "User Stories List Fecthed."})

    def delete_story_highlights(self, request, pk, format=None):
        user_obj = request.user
        stories_obj = UserStories.objects.filter(user = user_obj, id = pk, is_highlighted = True)
        if stories_obj:
           removed = UserStories.objects.filter(user = user_obj, id = pk).update(is_highlighted=False)
           return ({"data": [], "code": status.HTTP_200_OK, "message": "Story removed from highlight successfully"})
        else:
            return ({"data": [], "code": status.HTTP_200_OK, "message": "No record found"})