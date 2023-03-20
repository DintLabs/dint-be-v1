from api.models.UserSubscriptionModel import UserSubscription
from api.models.userSubscriptionTierModel import UserSubscriptionTier
from api.serializers.event import *
from api.utils import CustomPagination
from rest_framework import status
from api.utils.messages.commonMessages import *
from api.utils.messages.eventMessages import *

from .eventBaseService import EventBaseService


class EventService(EventBaseService):
    """
    Create, Retrieve, Update or Delete a Tier instance and Return all Tier.
    """

    def __init__(self):
        pass

    def get_events_by_user(self, request, pk, format=None):
        """
        Retun all the Tiers by User ID.
        """
        sub_obj = Events.objects.filter(user = pk)
        serializer = GetEventSerializer(sub_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": EVENTS_FETCHED})

    def create_event(self, request, format=None):
        """
        Create New Tier. 
        """
        serializer = CreateUpdateEventSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": EVENTS_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def delete_event(self, request, pk, format=None):
        """
        Delete Tier. 
        """
        try:
            sub_obj = Events.objects.get(id = pk)
        except Events.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        sub_obj.delete ()
        return ({"code": status.HTTP_200_OK, "message": EVENTS_DELETED})

    def update_event(self, request, pk, format=None):
        """
        Updates Post
        """
        data = request.data
        try:
            sub_obj = Events.objects.get(id = pk)
        except Events.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = CreateUpdateEventSerializer(sub_obj, data=data)
        if serializer.is_valid ():
            serializer.save ()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": EVENTS_UPDATED})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
     
    def get_event_by_id(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            sub_obj = Events.objects.get(id = pk)
        except Events.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        serializer = GetEventSerializer(sub_obj)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": EVENTS_FETCHED})

    def get_all_event(self, request, format=None):
        """
        Create New Tier. 
        """
        sub_obj = Events.objects.all()
        serializer = GetEventSerializer(sub_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": EVENTS_FETCHED})


    def get_venues_by_user(self, request, pk, format=None):
        """
        Retun all the Tiers by User ID.
        """
        sub_obj = Venue.objects.filter(user = pk)
        serializer = GetVenueSerializer(sub_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": VENUE_FETCHED})

    def create_venue(self, request, format=None):
        """
        Create New Tier. 
        """
        serializer = CreateUpdateVenueSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": VENUE_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def delete_venue(self, request, pk, format=None):
        """
        Delete Tier. 
        """
        try:
            sub_obj = Venue.objects.get(id = pk)
        except Venue.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        sub_obj.delete ()
        return ({"code": status.HTTP_200_OK, "message": VENUE_DELETED})

    def update_venue(self, request, pk, format=None):
        """
        Updates Post
        """
        data = request.data
        print('----------------_>>>')
        try:
            sub_obj = Venue.objects.get(id = pk)
        except Venue.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = CreateUpdateVenueSerializer(sub_obj, data=data)
        if serializer.is_valid ():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": VENUE_UPDATED})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
     
    def get_venue_by_id(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            sub_obj = Venue.objects.get(id = pk)
        except Venue.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        serializer = GetVenueSerializer(sub_obj)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": VENUE_FETCHED})

    def get_all_venue(self, request, format=None):
        """
        Create New Tier. 
        """
        sub_obj = Venue.objects.all()
        serializer = GetVenueSerializer(sub_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": VENUE_FETCHED})


