from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from api.services.events import EventService

eventService = EventService()

role_schema = AutoSchema(manual_fields=[
    coreapi.Field(
        "name",
        required=True,
        location="form",
        schema=coreschema.String()
    )
])


class ListCreateUpdateDeleteEventView(APIView):

    def get(self, request, format=None):
        """
        Retun all the Posts.
        """
        result = eventService.get_all_event(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create New Posts. 
        """
        result = eventService.create_event(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        """
        Updates Post
        """
        result = eventService.update_event(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk,  format=None):
        """
        Delete Posts. 
        """
        result = eventService.delete_event(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class GetEventByUserIDView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = eventService.get_events_by_user(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)



class GetEventByIDView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = eventService.get_event_by_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)




class ListCreateUpdateDeleteVenueView(APIView):

    def get(self, request, format=None):
        """
        Retun all the Posts.
        """
        result = eventService.get_all_venue(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create New Posts. 
        """
        result = eventService.create_venue(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        """
        Updates Post
        """
        result = eventService.update_venue(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk,  format=None):
        """
        Delete Posts. 
        """
        result = eventService.delete_venue(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class GetVenueByUserIDView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = eventService.get_venues_by_user(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)



class GetVenueByIDView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = eventService.get_venue_by_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)