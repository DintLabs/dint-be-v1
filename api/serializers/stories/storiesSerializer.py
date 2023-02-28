from rest_framework import serializers
from api.models.UserStoriesModel import *
from api.models.userFollowersModel import *
from api.serializers.user import UserLoginDetailSerializer
import datetime
from django.utils import timezone


class UserStoryLikesSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = UserStoriesLikes
        fields = "__all__"

class CreateUserStoriesSerrializer(serializers.ModelSerializer):
    class Meta:
        model = UserStories
        fields = "__all__"

class UserStoriesModelSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    liked_story = UserStoryLikesSerializer(many=True)
    total_likes = serializers.SerializerMethodField()

    class Meta:
        model = UserStories
        fields = "__all__"
        
    def get_name(self, obj):
        return obj.user.name

    def get_total_likes(self, obj):
        try:
            total_likes = UserStoriesLikes.objects.filter(story = obj).all().count()
            return total_likes
        except:
            return 0

class GetUserStoriesModelSerializer(serializers.ModelSerializer):
    user_stories = serializers.SerializerMethodField()
   
    class Meta(object):
        model = User
        fields = (
            'id', 'profile_image', 'display_name', 'custom_username',  'user_stories')

    def get_user_stories(self, obj):
        logged_in_user = self.context.get('logged_in_user')
        follower = UserFollowers.objects.filter(user=logged_in_user, request_status=True).values_list('follower')
        following = UserFollowers.objects.filter(follower=logged_in_user, request_status=True).values_list('user')
        users = following.union(follower)

        expire_time = timezone.now() - datetime.timedelta(hours=24)
        userstories = UserStories.objects.filter(user__in=users, created_at__gt = expire_time)
        serializer = UserStoriesModelSerializer(instance = userstories, many=True).data
        return serializer

class UserArchiveStorySerializer(serializers.ModelSerializer):
    class Meta(object):
        model = UserStories
        fields = "__all__"
