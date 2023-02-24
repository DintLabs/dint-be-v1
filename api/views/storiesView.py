from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from rest_framework.viewsets import ModelViewSet
from rest_framework import viewsets
from api.models import User, ConfineUsers, UserCustomLists, UserCustomGroupMembers
from api.models.userFollowersModel import UserFollowers
from api.serializers import ConfineModelSerializer, UserCustomListsModelSerializer, \
    UserCustomGroupMembersModelSerializer
from api.models.UserStoriesModel import *
from api.serializers.stories import UserStoriesModelSerializer
from api.services.stories import StoriesService
import datetime
from django.utils import timezone

storiesService = StoriesService()

class UserStoriesView(APIView):
    def get(self, request,format=None):
        """
        Retun all the Posts.
        """
        result = storiesService.get_stories(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request,format=None):
        """
        Retun all the Posts.
        """
        result = storiesService.create_stories(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk , format=None):
        """
        Retun all the Posts.
        """
        result = storiesService.delete_stories(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserStoriesByUserView(APIView):
    def get(self, request, format=None):
        """
        fetch stories of logged in user
        """
        result = storiesService.get_stories_by_user(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserLikeStories(APIView):
    def post(self, request, pk, format=None):
        """
        API to like the story
        """
        result = storiesService.like_stories(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def get(self, request, pk, format=None):
        """
        API to like the story
        """
        result = storiesService.get_stories_likes(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserUnlikeStories(APIView):
    def post(self, request, pk, format=None):
        """
        fetch stories of logged in user
        """
        result = storiesService.unlike_stories(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserStoryArchive(APIView):
    def post(self, request, format=None):
        """
        Create story archive
        """
        result = storiesService.create_story_archive(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def get(self, request, format=None):
        """
        Get Story Archive
        """
        result = storiesService.get_story_archive(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
    
    def delete(self, request, pk, format=None):
        """
        Delete story from archive
        """
        result = storiesService.delete_story_archive(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserStoriesHighlights(APIView):
    def post(self, request, format=None):
        """
        API to create story highlight
        """
        result = storiesService.create_story_highlight(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def get(self, request, format=None):
        """
        API to get story highlight
        """
        result = storiesService.get_story_highlights(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
    
    def delete(self, request, pk, format=None):
        """
        API to delete story highlight
        """
        result = storiesService.delete_story_highlights(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)