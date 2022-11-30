from multiprocessing import Event
from rest_framework import serializers
from api.models.userFollowersModel import UserFollowers, UserStories
from api.models.venueModel import Venue
from api.serializers.user import UserLoginDetailSerializer
from api.models.userModel import User
import datetime
from django.utils import timezone

class CreateUpdateConnectionSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = UserFollowers
        fields = '__all__'


class GetConnectionSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    user = UserLoginDetailSerializer()
    follower = UserLoginDetailSerializer()

    class Meta(object):
        model = UserFollowers
        fields = '__all__'


class UserStoriesModelSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()

    class Meta:
        model = UserStories
        exclude = ['updated_at', ]
        
    def get_name(self, obj):
        return obj.user.name


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