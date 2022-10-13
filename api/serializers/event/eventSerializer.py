from multiprocessing import Event
from rest_framework import serializers
from api.models.eventsModel import Events
from api.models.venueModel import Venue
from api.serializers.user import UserLoginDetailSerializer


class CreateUpdateEventSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = Events
        fields = '__all__'


class GetEventSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    user = UserLoginDetailSerializer()
    class Meta(object):
        model = Events
        fields = '__all__'


class CreateUpdateVenueSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = Venue
        fields = '__all__'


class GetVenueSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    user = UserLoginDetailSerializer()
    class Meta(object):
        model = Venue
        fields = '__all__'

  