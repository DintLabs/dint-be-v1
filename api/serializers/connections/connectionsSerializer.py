from multiprocessing import Event
from rest_framework import serializers
from api.models.userFollowersModel import UserFollowers, UserStories
from api.models.venueModel import Venue
from api.serializers.user import UserLoginDetailSerializer


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
