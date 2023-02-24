from multiprocessing import Event
from rest_framework import serializers
from api.models.userFollowersModel import UserFollowers
from api.models.UserStoriesModel import *
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

